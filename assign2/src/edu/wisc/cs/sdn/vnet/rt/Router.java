package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.MACAddress;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Timer;
import java.util.TimerTask;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	// below: table for dynamic rip data
	private Map<Integer, RipData> ripCollection;

	// some constants for rip and broadcast
	private static final String MAC_BROADCAST = "ff:ff:ff:ff:ff:ff";
	private static final String MAC_EMPTY     = "00:00:00:00:00:00";
	private static final String RIP_MULTICAST= "224.0.0.9";
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache   = new ArpCache();
		// initialize container for dynamic rip updates
		this.ripCollection = new ConcurrentHashMap<>();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ 
		return this.routeTable; 
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!this.routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!this.arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
			etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		/********************************************************************/

		// check if it's ipv4
		if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4)
		{
			IPv4 ipInner = (IPv4) etherPacket.getPayload();

			// if it might be rip traffic (multicast ip + udp + rip port)
			if ((ipInner.getDestinationAddress() == IPv4.toIPv4Address(RIP_MULTICAST))
					&& (ipInner.getProtocol() == IPv4.PROTOCOL_UDP))
			{
				UDP udpBody = (UDP) ipInner.getPayload();
				if (udpBody.getDestinationPort() == UDP.RIP_PORT)
				{
					RIPv2 ripCheck = (RIPv2) udpBody.getPayload();
					analyzeRipPacket(ripCheck.getCommand(), etherPacket, inIface);
					return;
				}
			}

			// if not rip, handle normal ip forwarding
			transferIpPacket(etherPacket, inIface);
		}
	}

	// an internal type for identifying different rip messages
	private enum RipPacketMode
	{
		REQUEST_MODE,
		RESPONSE_MODE,
		PERIODIC_MODE
	}

	/**
	 * a record class storing information about a learned rip route.
	 */
	private class RipData
	{
		public int address;     
		public int subnetMask;  
		public int nextHop;     
		public int metric;      
		public long timestamp;  

		public RipData(int netAddr, int netMask, int gateway, int dist, long time)
		{
			this.address    = netAddr;
			this.subnetMask = netMask;
			this.nextHop    = gateway;
			this.metric     = dist;
			this.timestamp  = time;
		}
	}

	/**
	 * initializes the dynamic rip process, including sending periodic advertisements
	 * and removing stale entries.
	 */
	public void initRipProcess()
	{
		// seed the table with our directly-connected networks
		for (Iface ifc : this.interfaces.values())
		{
			int mask = ifc.getSubnetMask();
			int net  = ifc.getIpAddress() & mask;

			ripCollection.put(net, new RipData(net, mask, 0, 0, Long.MIN_VALUE));
			this.routeTable.insert(net, 0, mask, ifc);

			// send an initial request
			dispatchRipPacket(RipPacketMode.REQUEST_MODE, null, ifc);
		}

		// set up periodic tasks
		TimerTask broadcastTask = new TimerTask()
		{
			public void run()
			{
				// send unsolicited rip updates every 10s
				for (Iface out : interfaces.values())
				{
					dispatchRipPacket(RipPacketMode.PERIODIC_MODE, null, out);
				}
			}
		};

		TimerTask staleCleanup = new TimerTask()
		{
			public void run()
			{
				long now = System.currentTimeMillis();
				ArrayList<Integer> removeList = new ArrayList<>();
				
				synchronized (ripCollection)
				{
					for (Map.Entry<Integer, RipData> e : ripCollection.entrySet())
					{
						RipData stored = e.getValue();
						// if more than 30s passed, remove
						if (stored.timestamp >= 0 && (now - stored.timestamp) >= 30000)
						{
							removeList.add(stored.address & stored.subnetMask);
						}
					}
					for (Integer netKey : removeList)
					{
						RipData oldOne = ripCollection.remove(netKey);
						if (oldOne != null)
						{
							routeTable.remove(oldOne.address, oldOne.subnetMask);
						}
					}
				}
			}
		};

		// schedule tasks
		Timer mainClock = new Timer(true);
		mainClock.schedule(broadcastTask, 0, 10000); // every 10s
		mainClock.schedule(staleCleanup, 0, 1000);   // check timeouts frequently
	}

	/**
	 * transfers a normal ipv4 packet to the next hop, verifying checksum, ttl, etc.
	 */
	private void transferIpPacket(Ethernet etherPacket, Iface inIface)
	{
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{
			return;
		}

		IPv4 ipH = (IPv4) etherPacket.getPayload();

		// verify checksum
		short oldSum = ipH.getChecksum();
		ipH.setChecksum((short) 0);
		byte[] scratch = ipH.serialize();
		IPv4 recheck = (IPv4) ipH.deserialize(scratch, 0, scratch.length);
		if (oldSum != recheck.getChecksum())
		{
			return; // drop
		}

		// decrement ttl
		byte updatedTtl = (byte)(ipH.getTtl() - 1);
		if (updatedTtl <= 0)
		{
			return; // drop
		}
		ipH.setTtl(updatedTtl);

		// recalc checksum
		ipH.setChecksum((short) 0);
		byte[] raw2 = ipH.serialize();
		ipH = (IPv4) ipH.deserialize(raw2, 0, raw2.length);
		etherPacket.setPayload(ipH);

		// drop if the destination matches any of our interfaces
		for (Iface localIf : this.interfaces.values())
		{
			if (localIf.getIpAddress() == ipH.getDestinationAddress())
			{
				return;
			}
		}

		// lookup next hop in route table
		RouteEntry route = this.routeTable.lookup(ipH.getDestinationAddress());
		if (route == null)
		{
			return; // no route => drop
		}

		int gateway = route.getGatewayAddress();
		int nextAddr = (gateway != 0) ? gateway : ipH.getDestinationAddress();

		// lookup in arp cache
		ArpEntry found = this.arpCache.lookup(nextAddr);
		if (found == null)
		{
			return; // cannot forward, drop
		}
		MACAddress destMac = found.getMac();
		Iface outPort = route.getInterface();
		if (destMac == null || outPort == null || outPort.getMacAddress() == null)
		{
			return; // avoid null pointer
		}

		// set new mac addresses, send out
		etherPacket.setDestinationMACAddress(destMac.toBytes());
		etherPacket.setSourceMACAddress(outPort.getMacAddress().toBytes());
		sendPacket(etherPacket, outPort);
	}

	/**
	 * creates and sends a rip packet of the specified type.
	 */
	private void dispatchRipPacket(RipPacketMode mode, Ethernet inboundPkt, Iface outIf)
	{
		// check for valid interface
		if (outIf == null || outIf.getMacAddress() == null)
		{
			return;
		}

		Ethernet newEth = new Ethernet();
		IPv4 newIp = new IPv4();
		UDP newUdp = new UDP();
		RIPv2 newRip = new RIPv2();

		// fill out layers
		newEth.setEtherType(Ethernet.TYPE_IPv4);
		newEth.setSourceMACAddress(outIf.getMacAddress().toBytes());

		newIp.setProtocol(IPv4.PROTOCOL_UDP);
		newIp.setTtl((byte)64);
		newIp.setSourceAddress(outIf.getIpAddress());

		newUdp.setSourcePort(UDP.RIP_PORT);
		newUdp.setDestinationPort(UDP.RIP_PORT);

		// choose addressing based on mode
		switch (mode)
		{
			case PERIODIC_MODE:
				newRip.setCommand(RIPv2.COMMAND_RESPONSE);
				newEth.setDestinationMACAddress(MAC_BROADCAST);
				newIp.setDestinationAddress(IPv4.toIPv4Address(RIP_MULTICAST));
				break;
			case REQUEST_MODE:
				newRip.setCommand(RIPv2.COMMAND_REQUEST);
				newEth.setDestinationMACAddress(MAC_BROADCAST);
				newIp.setDestinationAddress(IPv4.toIPv4Address(RIP_MULTICAST));
				break;
			case RESPONSE_MODE:
				if (inboundPkt == null)
				{
					// no inbound => can't respond specifically
					return;
				}
				IPv4 ipIn = (IPv4) inboundPkt.getPayload();
				newRip.setCommand(RIPv2.COMMAND_RESPONSE);
				newEth.setDestinationMACAddress(inboundPkt.getSourceMACAddress());
				newIp.setDestinationAddress(ipIn.getSourceAddress());
				break;
			default:
				return;
		}

		// build the list of rip entries
		List<RIPv2Entry> appended = new ArrayList<>();
		synchronized (ripCollection)
		{
			for (RipData d : ripCollection.values())
			{
				RIPv2Entry e = new RIPv2Entry(d.address, d.subnetMask, d.metric);
				appended.add(e);
			}
		}
		newRip.setEntries(appended);

		// assemble the payload chain
		newUdp.setPayload(newRip);
		newIp.setPayload(newUdp);
		newEth.setPayload(newIp);

		sendPacket(newEth, outIf);
	}

	/**
	 * processes incoming rip requests/responses.
	 */
	private void analyzeRipPacket(byte ripCmd, Ethernet ethFrame, Iface receivingIf)
	{
		switch (ripCmd)
		{
			case RIPv2.COMMAND_REQUEST:
				dispatchRipPacket(RipPacketMode.RESPONSE_MODE, ethFrame, receivingIf);
				break;
			case RIPv2.COMMAND_RESPONSE:
			{
				IPv4 ipSec = (IPv4) ethFrame.getPayload();
				UDP udpSec = (UDP) ipSec.getPayload();
				RIPv2 dataSec = (RIPv2) udpSec.getPayload();
				List<RIPv2Entry> allEntries = dataSec.getEntries();

				for (RIPv2Entry en : allEntries)
				{
					int netAddr = en.getAddress();
					int netMask = en.getSubnetMask();
					int nextHp  = ipSec.getSourceAddress();
					int newDist = en.getMetric() + 1;
					if (newDist > 16) newDist = 16; // 'infinite'

					int key = netAddr & netMask;
					synchronized (ripCollection)
					{
						RipData oldDat = ripCollection.get(key);
						if (oldDat != null)
						{
							// update if new metric is better or same
							if (newDist <= oldDat.metric)
							{
								oldDat.metric    = newDist;
								oldDat.timestamp = System.currentTimeMillis();
								oldDat.nextHop   = nextHp;
								routeTable.update(netAddr, netMask, nextHp, receivingIf);
							}

							// if newDist is infinite, remove if we route out same iface
							if (newDist == 16)
							{
								RouteEntry current = routeTable.lookup(netAddr);
								if (current != null && current.getInterface().equals(receivingIf))
								{
									oldDat.metric = 16;
									routeTable.remove(netAddr, netMask);
								}
							}
						}
						else
						{
							// brand new entry if not infinite
							if (newDist < 16)
							{
								RipData fresh = new RipData(netAddr, netMask, nextHp,
										newDist, System.currentTimeMillis());
								ripCollection.put(key, fresh);
								routeTable.insert(netAddr, nextHp, netMask, receivingIf);
							}
						}
					}
				}
				break;
			}
			default:
				break;
		}
	}
}

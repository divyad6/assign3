package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.ArrayList;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	// rip table for dynamic routing data
	private Map<Integer, RipRecord> ripEntries;

	// constants for rip, arp, etc.
	private static final String MAC_BCAST    = "ff:ff:ff:ff:ff:ff";
	private static final String MAC_ZERO     = "00:00:00:00:00:00";
	private static final String IP_RIP_GROUP = "224.0.0.9";

	/**
	 * creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache   = new ArpCache();
		this.ripEntries = new ConcurrentHashMap<>();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ 
		return this.routeTable; 
	}
	
	/**
	 * load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
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
	 * load a new arp cache from a file.
	 * @param arpCacheFile the name of the file containing the arp cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
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
	 * handle an ethernet packet received on a specific interface.
	 * @param etherPacket the ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		/********************************************************************/
		
		// check if ipv4
		if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4)
		{
			IPv4 ipPayload = (IPv4) etherPacket.getPayload();

			// check if packet is destined to rip multicast with udp/rip port
			if (ipPayload.getDestinationAddress() == IPv4.toIPv4Address(IP_RIP_GROUP)
					&& ipPayload.getProtocol() == IPv4.PROTOCOL_UDP)
			{
				UDP udpData = (UDP) ipPayload.getPayload();
				if (udpData.getDestinationPort() == UDP.RIP_PORT)
				{
					RIPv2 possibleRip = (RIPv2) udpData.getPayload();
					processRipPacket(possibleRip.getCommand(), etherPacket, inIface);
					return;
				}
			}

			// otherwise handle normal ipv4 forwarding
			forwardIpPacket(etherPacket, inIface);
		}
	}

	// enumerates internal message types for rip
	private enum RipMsgType
	{
		RIP_REQUEST,
		RIP_RESPONSE,
		RIP_UNSOLICITED
	}

	/**
	 * small record class for storing rip state.
	 */
	private class RipRecord
	{
		public int address;
		public int subnetMask;
		public int nextHop;
		public int metric;
		public long lastUpdate;

		public RipRecord(int addr, int mask, int gw, int dist, long timestamp)
		{
			this.address    = addr;
			this.subnetMask = mask;
			this.nextHop    = gw;
			this.metric     = dist;
			this.lastUpdate = timestamp;
		}
	}

	/**
	 * initializes the router's rip process to dynamically learn routes, 
	 * sending periodic announcements and timing out stale entries.
	 */
	public void initRipProcess()
	{
		// set up each directly-connected network
		for (Iface iface : this.interfaces.values())
		{
			int netMask = iface.getSubnetMask();
			int netAddr = iface.getIpAddress() & netMask;

			// populate local rip table and route table
			ripEntries.put(netAddr, new RipRecord(netAddr, netMask, 0, 0, Integer.MIN_VALUE));
			routeTable.insert(netAddr, 0, netMask, iface);

			// broadcast a rip request for each interface
			emitRipPacket(RipMsgType.RIP_REQUEST, null, iface);
		}

		// set up periodic tasks
		TimerTask unsolicitedTask = new TimerTask()
		{
			public void run()
			{
				// send unsolicited responses every 10 seconds
				for (Iface outFace : interfaces.values())
				{
					emitRipPacket(RipMsgType.RIP_UNSOLICITED, null, outFace);
				}
			}
		};

		TimerTask timeoutTask = new TimerTask()
		{
			public void run()
			{
				long now = System.currentTimeMillis();
				ArrayList<Integer> toRemove = new ArrayList<>();
				
				synchronized (ripEntries)
				{
					for (Map.Entry<Integer, RipRecord> e : ripEntries.entrySet())
					{
						RipRecord rec = e.getValue();
						// if lastUpdate < 0 => it's directly connected or not yet updated
						if (rec.lastUpdate >= 0 && (now - rec.lastUpdate) >= 30000)
						{
							toRemove.add(rec.address & rec.subnetMask);
						}
					}
					// remove timed-out entries
					for (Integer key : toRemove)
					{
						RipRecord oldRec = ripEntries.remove(key);
						if (oldRec != null)
						{
							routeTable.remove(oldRec.address, oldRec.subnetMask);
						}
					}
				}
			}
		};

		Timer mainTimer = new Timer(true);
		// unsolicited updates every 10s
		mainTimer.schedule(unsolicitedTask, 0, 10000);
		// check timeouts more frequently (e.g., 1s)
		mainTimer.schedule(timeoutTask, 0, 1000);
	}

	/**
	 * forwards a normal ipv4 packet after decrementing ttl, verifying checksum, etc.
	 */
	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{
			return; // not ipv4 => drop
		}

		IPv4 ipHdr = (IPv4) etherPacket.getPayload();

		// verify checksum
		short origCsum = ipHdr.getChecksum();
		ipHdr.setChecksum((short)0);
		byte[] data = ipHdr.serialize();
		IPv4 reloaded = (IPv4) ipHdr.deserialize(data, 0, data.length);
		if (origCsum != reloaded.getChecksum())
		{
			return; // checksum mismatch => drop
		}

		// decrement ttl
		byte newTtl = (byte)(ipHdr.getTtl() - 1);
		if (newTtl <= 0)
		{
			return; // ttl expired => drop
		}
		ipHdr.setTtl(newTtl);

		// recalc checksum
		ipHdr.setChecksum((short)0);
		byte[] updated = ipHdr.serialize();
		ipHdr = (IPv4) ipHdr.deserialize(updated, 0, updated.length);
		etherPacket.setPayload(ipHdr);

		// if destination is one of our interfaces => drop
		for (Iface localIf : this.interfaces.values())
		{
			if (localIf.getIpAddress() == ipHdr.getDestinationAddress())
			{
				return; 
			}
		}

		// lookup next hop
		RouteEntry match = this.routeTable.lookup(ipHdr.getDestinationAddress());
		if (match == null)
		{
			return; // no route => drop
		}

		int gw = match.getGatewayAddress();
		int nextIp = (gw != 0) ? gw : ipHdr.getDestinationAddress();

		// check arp cache
		ArpEntry resolved = this.arpCache.lookup(nextIp);
		if (resolved == null)
		{
			// no arp => drop (or attempt arp request, depends on assignment)
			return;
		}

		// set mac addresses and send
		etherPacket.setDestinationMACAddress(resolved.getMac().toBytes());
		etherPacket.setSourceMACAddress(match.getInterface().getMacAddress().toBytes());
		sendPacket(etherPacket, match.getInterface());
	}

	/**
	 * creates and sends a rip packet of a certain type on the specified interface.
	 */
	private void emitRipPacket(RipMsgType type, Ethernet inFrame, Iface outIface)
	{
		// guard against null interface
		if (outIface == null || outIface.getMacAddress() == null)
		{
			return; 
		}

		Ethernet ether = new Ethernet();
		IPv4 ipLayer = new IPv4();
		UDP udpLayer = new UDP();
		RIPv2 ripData = new RIPv2();

		// fill in ether header
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// fill in ip header
		ipLayer.setTtl((byte)64);
		ipLayer.setProtocol(IPv4.PROTOCOL_UDP);
		ipLayer.setSourceAddress(outIface.getIpAddress());

		// fill in udp
		udpLayer.setSourcePort(UDP.RIP_PORT);
		udpLayer.setDestinationPort(UDP.RIP_PORT);

		// decide packet addressing depending on type
		switch (type)
		{
			case RIP_UNSOLICITED:
				// broad/multicast response
				ripData.setCommand(RIPv2.COMMAND_RESPONSE);
				ether.setDestinationMACAddress(MAC_BCAST);
				ipLayer.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_GROUP));
				break;
			case RIP_REQUEST:
				ripData.setCommand(RIPv2.COMMAND_REQUEST);
				ether.setDestinationMACAddress(MAC_BCAST);
				ipLayer.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_GROUP));
				break;
			case RIP_RESPONSE:
				// responding directly to a request
				if (inFrame == null)
				{
					// original logic never sends a response if we don't have an inbound
					return; 
				}
				IPv4 inboundIp = (IPv4) inFrame.getPayload();
				ripData.setCommand(RIPv2.COMMAND_RESPONSE);
				ether.setDestinationMACAddress(inFrame.getSourceMACAddress());
				ipLayer.setDestinationAddress(inboundIp.getSourceAddress());
				break;
			default:
				return;
		}

		// gather current rip entries
		List<RIPv2Entry> ripEntriesList = new ArrayList<>();
		synchronized (ripEntries)
		{
			for (RipRecord record : ripEntries.values())
			{
				RIPv2Entry e = new RIPv2Entry(record.address, record.subnetMask, record.metric);
				ripEntriesList.add(e);
			}
		}
		ripData.setEntries(ripEntriesList);

		// assemble
		udpLayer.setPayload(ripData);
		ipLayer.setPayload(udpLayer);
		ether.setPayload(ipLayer);

		sendPacket(ether, outIface);
	}

	/**
	 * processes a received rip packet (request or response).
	 */
	private void processRipPacket(byte command, Ethernet frame, Iface inIface)
	{
		switch (command)
		{
			case RIPv2.COMMAND_REQUEST:
				// immediate response
				emitRipPacket(RipMsgType.RIP_RESPONSE, frame, inIface);
				break;
			case RIPv2.COMMAND_RESPONSE:
			{
				IPv4 ipPortion = (IPv4) frame.getPayload();
				UDP udpPortion = (UDP) ipPortion.getPayload();
				RIPv2 ripBody  = (RIPv2) udpPortion.getPayload();
				List<RIPv2Entry> entriesList = ripBody.getEntries();

				for (RIPv2Entry entry : entriesList)
				{
					int netAddr = entry.getAddress();
					int netMask = entry.getSubnetMask();
					int nextHop = ipPortion.getSourceAddress();
					int newMetric = entry.getMetric() + 1;
					if (newMetric > 16) newMetric = 16; // 'infinity'

					int key = netAddr & netMask;
					
					synchronized (ripEntries)
					{
						RipRecord oldRec = ripEntries.get(key);
						if (oldRec != null)
						{
							// if new metric is better or equal, update
							if (newMetric <= oldRec.metric)
							{
								oldRec.metric     = newMetric;
								oldRec.lastUpdate = System.currentTimeMillis();
								oldRec.nextHop    = nextHop;
								routeTable.update(netAddr, netMask, nextHop, inIface);
							}
							// if 'infinite' and our route is via the same iface => remove
							if (newMetric == 16)
							{
								RouteEntry current = routeTable.lookup(netAddr);
								if (current != null && current.getInterface().equals(inIface))
								{
									oldRec.metric = 16;
									routeTable.remove(netAddr, netMask);
								}
							}
						}
						else
						{
							// add new route if not infinite
							if (newMetric < 16)
							{
								RipRecord newRec = new RipRecord(netAddr, netMask, nextHop,
										newMetric, System.currentTimeMillis());
								ripEntries.put(key, newRec);
								routeTable.insert(netAddr, nextHop, netMask, inIface);
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

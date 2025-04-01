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

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();

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
	 * Load a new routing table from a file.
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
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
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
		short etherType = etherPacket.getEtherType();

		if (etherType == Ethernet.TYPE_IPv4)
		{
			IPv4 ipv4Data = (IPv4) etherPacket.getPayload();

			// check if it's potentially RIP packet
			if (ipv4Data.getDestinationAddress() == IPv4.toIPv4Address(IP_RIP_GROUP) 
					&& ipv4Data.getProtocol() == IPv4.PROTOCOL_UDP)
			{
				UDP udpSegment = (UDP) ipv4Data.getPayload();
				if (udpSegment.getDestinationPort() == UDP.RIP_PORT)
				{
					RIPv2 potentialRip = (RIPv2) udpSegment.getPayload();
					processRipPacket(potentialRip.getCommand(), etherPacket, inIface);
					return;
				}
			}
			
			forwardIpPacket(etherPacket, inIface);
		}
		/********************************************************************/
	}

	private enum RipMessageType
	{
		RIP_REQUEST,
		RIP_RESPONSE,
		RIP_PERIODIC
	}

	// constants
	private static final String MAC_BCAST       = "ff:ff:ff:ff:ff:ff";
	private static final String MAC_NULL        = "00:00:00:00:00:00";
	private static final String IP_RIP_GROUP    = "224.0.0.9";


	private class RipRecord 
	{
		public int address;
		public int subnetMask;
		public int nextHop;
		public int metric;
		public long lastUpdated;  // for timeouts

		public RipRecord(int addr, int mask, int gw, int dist, long time)
		{
			this.address    = addr;
			this.subnetMask = mask;
			this.nextHop    = gw;
			this.metric     = dist;
			this.lastUpdated= time;
		}
	}

	// map of RIP table entries
	private Map<Integer, RipRecord> ripEntries;

	/**
	 * initialize RIP for dynamic routing.
	 * creates periodic tasks to send RIP updates and to expire stale entries
	 */
	public void initRipProcess()
	{
		for (Iface netIf : this.interfaces.values())
		{
			int netMask = netIf.getSubnetMask();
			int ifaceNetAddr = netIf.getIpAddress() & netMask;

			ripEntries.put(ifaceNetAddr, new RipRecord(ifaceNetAddr, netMask, 0, 0, Long.MIN_VALUE));
			this.routeTable.insert(ifaceNetAddr, 0, netMask, netIf);

			// send an initial RIP request out each interface
			emitRipPacket(RipMessageType.RIP_REQUEST, null, netIf);
		}

		// periodically emit unsolicited RIP advertisements
		TimerTask advTask = new TimerTask()
		{
			public void run()
			{
				for (Iface outIf : interfaces.values())
				{
					emitRipPacket(RipMessageType.RIP_PERIODIC, null, outIf);
				}
			}
		};

		// timer task for expiring old entries
		TimerTask expireTask = new TimerTask()
		{
			public void run()
			{
				synchronized (ripEntries)
				{
					ArrayList<Integer> toRemove = new ArrayList<>();
					for (Map.Entry<Integer, RipRecord> item : ripEntries.entrySet())
					{
						RipRecord rec = item.getValue();
						if (rec.lastUpdated >= 0 && 
							(System.currentTimeMillis() - rec.lastUpdated) >= 30000)
						{
							toRemove.add(rec.address & rec.subnetMask);
						}
					}
					for (Integer net : toRemove)
					{
						RipRecord oldRec = ripEntries.remove(net);
						if (oldRec != null)
						{
							thisRef.routeTable.remove(oldRec.address, oldRec.subnetMask);
						}
					}
				}
			}

			private Router thisRef = Router.this;
		};


		// start timers
		Timer globalTimer = new Timer(true);
		globalTimer.schedule(advTask, 0, 10000);     
		globalTimer.schedule(expireTask, 0, 30000);  // check for timeouts (30 second limit)
	}

	/**
	 * forwards a normal IP packet 
	 */
	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// ignore if not ipv4
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{
			return; 
		}

		IPv4 ipHeader = (IPv4) etherPacket.getPayload();
		// validate checksum
		short origCsum = ipHeader.getChecksum();
		ipHeader.setChecksum((short) 0);
		byte[] serialized = ipHeader.serialize();
		IPv4 reDeserialized = (IPv4) ipHeader.deserialize(serialized, 0, serialized.length);
		if (origCsum != reDeserialized.getChecksum())
		{
			return; // bad checksum -> drop
		}

		// decrement TTL
		byte updatedTTL = (byte) (ipHeader.getTtl() - 1);
		if (updatedTTL <= 0) 
		{
			return; // TTL expired -> drop
		}
		ipHeader.setTtl(updatedTTL);

		// recompute checksum after TTL change
		ipHeader.setChecksum((short) 0);
		byte[] newData = ipHeader.serialize();
		ipHeader = (IPv4) ipHeader.deserialize(newData, 0, newData.length);
		etherPacket.setPayload(ipHeader);

		// check if destined for one of our interfaces -> if so, drop
		for (Iface localIf : this.interfaces.values())
		{
			if (localIf.getIpAddress() == ipHeader.getDestinationAddress())
			{ return; }
		}

		// look up next hop in route table
		RouteEntry bestMatch = routeTable.lookup(ipHeader.getDestinationAddress());
		if (bestMatch == null)
		{
			return; 
		}

		int gatewayAddr = bestMatch.getGatewayAddress();
		int nextIp = (gatewayAddr != 0) ? gatewayAddr : ipHeader.getDestinationAddress();

		ArpEntry foundArp = arpCache.lookup(nextIp);
		if (foundArp == null)
		{
			return; 
		}

		etherPacket.setDestinationMACAddress(foundArp.getMac().toBytes());
		etherPacket.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());
		sendPacket(etherPacket, bestMatch.getInterface());
	}

	private void emitRipPacket(RipMessageType whichType, Ethernet inbound, Iface outIface)
	{
		Ethernet newFrame = new Ethernet();
		IPv4 ipSlice     = new IPv4();
		UDP udpSlice     = new UDP();
		RIPv2 ripPayload = new RIPv2();

		newFrame.setEtherType(Ethernet.TYPE_IPv4);
		newFrame.setSourceMACAddress(outIface.getMacAddress().toBytes());

		ipSlice.setTtl((byte)64); 
		ipSlice.setProtocol(IPv4.PROTOCOL_UDP);
		ipSlice.setSourceAddress(outIface.getIpAddress());

		udpSlice.setSourcePort(UDP.RIP_PORT);
		udpSlice.setDestinationPort(UDP.RIP_PORT);

		// decide how we fill in the destination MAC/IP based on type
		switch (whichType)
		{
			case RIP_PERIODIC:
				ripPayload.setCommand(RIPv2.COMMAND_RESPONSE);
				newFrame.setDestinationMACAddress(MAC_BCAST);
				ipSlice.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_GROUP));
				break;
			case RIP_REQUEST:
				ripPayload.setCommand(RIPv2.COMMAND_REQUEST);
				newFrame.setDestinationMACAddress(MAC_BCAST);
				ipSlice.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_GROUP));
				break;
			case RIP_RESPONSE:
				if (inbound != null)
				{
					IPv4 originalIp = (IPv4) inbound.getPayload();
					ripPayload.setCommand(RIPv2.COMMAND_RESPONSE);
					newFrame.setDestinationMACAddress(inbound.getSourceMACAddress());
					ipSlice.setDestinationAddress(originalIp.getSourceAddress());
				}
				break;
			default:
				break;
		}

		// get curr RIP data
		List<RIPv2Entry> aggregated = new ArrayList<>();
		synchronized (this.ripEntries)
		{
			for (RipRecord r : this.ripEntries.values())
			{
				RIPv2Entry e = new RIPv2Entry(r.address, r.subnetMask, r.metric);
				aggregated.add(e);
			}
		}

		ripPayload.setEntries(aggregated);
		ipSlice.setPayload(udpSlice);
		udpSlice.setPayload(ripPayload);
		newFrame.setPayload(ipSlice);

		sendPacket(newFrame, outIface);
	}

	/**
	 * processes an incoming RIP packet 
	 */
	private void processRipPacket(byte ripCmdType, Ethernet originalFrame, Iface inPort)
	{
		switch (ripCmdType)
		{
			case RIPv2.COMMAND_REQUEST:
				emitRipPacket(RipMessageType.RIP_RESPONSE, originalFrame, inPort);
				break;
			case RIPv2.COMMAND_RESPONSE:
				IPv4 ipLayer = (IPv4) originalFrame.getPayload();
				UDP udpPart  = (UDP) ipLayer.getPayload();
				RIPv2 ripSeg = (RIPv2) udpPart.getPayload();
				List<RIPv2Entry> dataList = ripSeg.getEntries();

				for (RIPv2Entry item : dataList)
				{
					int netAddr = item.getAddress();
					int netMask = item.getSubnetMask();
					int possibleNextHop = ipLayer.getSourceAddress();
					int newMetric = item.getMetric() + 1;
					if (newMetric > 16) { newMetric = 16; } // inf

					int netKey = netAddr & netMask;
					
					synchronized (ripEntries)
					{
						RipRecord existing = ripEntries.get(netKey);
						if (existing != null)
						{
							// if new distance is better or equal, update
							if (newMetric <= existing.metric)
							{
								existing.metric = newMetric;
								existing.lastUpdated = System.currentTimeMillis();
								existing.nextHop = possibleNextHop;
								routeTable.update(netAddr, netMask, possibleNextHop, inPort);
							}
							
							// if new metric is infinite and we route out this interface, remove
							if (newMetric == 16)
							{
								RouteEntry current = routeTable.lookup(netAddr);
								if (current != null && current.getInterface().equals(inPort))
								{
									existing.metric = 16;
									routeTable.remove(netAddr, netMask);
								}
							}
						}
						else
						{
							// insert brand-new entry if metric not infinite
							RipRecord fresh = new RipRecord(netAddr, netMask, 
									possibleNextHop, newMetric, System.currentTimeMillis());
							ripEntries.put(netKey, fresh);
							if (newMetric < 16)
							{
								routeTable.insert(netAddr, possibleNextHop, netMask, inPort);
							}
						}
					}
				}
				break;
			default:
				break;
		}
	}
}

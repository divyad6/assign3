package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.MACAddress;

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

	// rip table for dynamic routing
	private Map<Integer, RipRecord> ripEntries;

	// constants 
	private static final String MAC_BCAST    = "ff:ff:ff:ff:ff:ff";
	private static final String IP_RIP_GROUP = "224.0.0.9";


	public Router(String host, DumpFile logfile)
	{
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache   = new ArpCache();
		this.ripEntries = new ConcurrentHashMap<>();
	}


	public RouteTable getRouteTable()
	{ 
		return this.routeTable; 
	}

	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		/********************************************************************/
		
		if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4)
		{
			IPv4 ipLayer = (IPv4) etherPacket.getPayload();

			// check if it's rip
			if (ipLayer.getDestinationAddress() == IPv4.toIPv4Address(IP_RIP_GROUP)
					&& ipLayer.getProtocol() == IPv4.PROTOCOL_UDP)
			{
				UDP udpSeg = (UDP) ipLayer.getPayload();
				if (udpSeg.getDestinationPort() == UDP.RIP_PORT)
				{
					RIPv2 maybeRip = (RIPv2) udpSeg.getPayload();
					processRipPacket(maybeRip.getCommand(), etherPacket, inIface);
					return;
				}
			}

			// otherwise normal ip forwarding
			forwardIpPacket(etherPacket, inIface);
		}
	}

	private enum RipMsgType
	{
		RIP_REQUEST,
		RIP_RESPONSE,
		RIP_UNSOLICITED
	}

	/**
	 * simple container for storing rip state
	 */
	private class RipRecord
	{
		public int address;
		public int subnetMask;
		public int nextHop;
		public int metric;
		public long lastUpdate;

		public RipRecord(int addr, int mask, int nhop, int dist, long timestamp)
		{
			this.address    = addr;
			this.subnetMask = mask;
			this.nextHop    = nhop;
			this.metric     = dist;
			this.lastUpdate = timestamp;
		}
	}

	/**
	 * initialize the rip process to dynamically learn and refresh routes.
	 */
	public void initRipProcess()
	{
		// directly connected networks
		for (Iface iface : this.interfaces.values())
		{
			int mask = iface.getSubnetMask();
			int base = iface.getIpAddress() & mask;

			ripEntries.put(base, new RipRecord(base, mask, 0, 0, Integer.MIN_VALUE));
			this.routeTable.insert(base, 0, mask, iface);

			emitRipPacket(RipMsgType.RIP_REQUEST, null, iface);
		}

		TimerTask periodicTask = new TimerTask()
		{
			public void run()
			{
				for (Iface out : interfaces.values())
				{
					emitRipPacket(RipMsgType.RIP_UNSOLICITED, null, out);
				}
			}
		};

		TimerTask cleanupTask = new TimerTask()
		{
			public void run()
			{
				long now = System.currentTimeMillis();
				ArrayList<Integer> toDel = new ArrayList<>();

				synchronized (ripEntries)
				{
					for (Map.Entry<Integer, RipRecord> r : ripEntries.entrySet())
					{
						RipRecord rec = r.getValue();
						if (rec.lastUpdate >= 0 && (now - rec.lastUpdate) >= 30000)
						{
							toDel.add(rec.address & rec.subnetMask);
						}
					}
					for (Integer k : toDel)
					{
						RipRecord dead = ripEntries.remove(k);
						if (dead != null)
						{
							routeTable.remove(dead.address, dead.subnetMask);
						}
					}
				}
			}
		};

		Timer mainTimer = new Timer(true);
		// send unsolicited every 10 sec
		mainTimer.schedule(periodicTask, 0, 10000);
		// check expired entries every 30 sec
		mainTimer.schedule(cleanupTask, 0, 30000);
	}

	/**
	 * forwards a normal ipv4 packet, verifying checksum, decrementing ttl, etc.
	 */
	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{
			return; 
		}

		IPv4 ipHdr = (IPv4) etherPacket.getPayload();

		// verify checksum
		short origSum = ipHdr.getChecksum();
		ipHdr.setChecksum((short)0);
		byte[] rawData = ipHdr.serialize();
		IPv4 reloaded = (IPv4) ipHdr.deserialize(rawData, 0, rawData.length);
		if (origSum != reloaded.getChecksum())
		{
			return; 
		}

		// decrement ttl
		byte newTtl = (byte)(ipHdr.getTtl() - 1);
		if (newTtl <= 0)
		{
			return; 
		}
		ipHdr.setTtl(newTtl);
		ipHdr.setChecksum((short)0);

		byte[] up = ipHdr.serialize();
		ipHdr = (IPv4) ipHdr.deserialize(up, 0, up.length);
		etherPacket.setPayload(ipHdr);

		// if dest is one of our interfaces -> drop
		for (Iface localIf : this.interfaces.values())
		{
			if (localIf.getIpAddress() == ipHdr.getDestinationAddress())
			{
				return;
			}
		}

		// lookup route
		RouteEntry bestMatch = this.routeTable.lookup(ipHdr.getDestinationAddress());
		if (bestMatch == null)
		{
			return;
		}

		int gw = bestMatch.getGatewayAddress();
		int nextIp = (gw != 0) ? gw : ipHdr.getDestinationAddress();

		// lookup in arp
		ArpEntry resolved = this.arpCache.lookup(nextIp);
		if (resolved == null)
		{
			return;
		}
		MACAddress resolvedMac = resolved.getMac();
		Iface outIface = bestMatch.getInterface();

		if (resolvedMac == null || outIface == null || outIface.getMacAddress() == null)
		{
			return; 
		}

		etherPacket.setDestinationMACAddress(resolvedMac.toBytes());
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
		sendPacket(etherPacket, outIface);
	}



	private void emitRipPacket(RipMsgType type, Ethernet inbound, Iface outIface)
	{
		// avoid null pointers
		if (outIface == null || outIface.getMacAddress() == null)
		{
			return;
		}

		Ethernet ether = new Ethernet();
		IPv4 ipLayer   = new IPv4();
		UDP udpLayer   = new UDP();
		RIPv2 ripData  = new RIPv2();

		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());

		ipLayer.setTtl((byte)64);
		ipLayer.setProtocol(IPv4.PROTOCOL_UDP);
		ipLayer.setSourceAddress(outIface.getIpAddress());

		udpLayer.setSourcePort(UDP.RIP_PORT);
		udpLayer.setDestinationPort(UDP.RIP_PORT);

		switch (type)
		{
			case RIP_UNSOLICITED:
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
				if (inbound == null)
				{
					// if no inbound frame, we can't respond specifically
					return;
				}
				IPv4 inboundIp = (IPv4) inbound.getPayload();
				ripData.setCommand(RIPv2.COMMAND_RESPONSE);
				ether.setDestinationMACAddress(inbound.getSourceMACAddress());
				ipLayer.setDestinationAddress(inboundIp.getSourceAddress());
				break;
			default:
				return;
		}

		// build current rip table
		List<RIPv2Entry> entries = new ArrayList<>();
		synchronized (ripEntries)
		{
			for (RipRecord r : ripEntries.values())
			{
				RIPv2Entry e = new RIPv2Entry(r.address, r.subnetMask, r.metric);
				entries.add(e);
			}
		}
		ripData.setEntries(entries);

		udpLayer.setPayload(ripData);
		ipLayer.setPayload(udpLayer);
		ether.setPayload(ipLayer);

		sendPacket(ether, outIface);
	}

	/**
	 * processes an incoming rip packet
	 */
	private void processRipPacket(byte command, Ethernet inFrame, Iface inIface)
	{
		switch (command)
		{
			case RIPv2.COMMAND_REQUEST:
				emitRipPacket(RipMsgType.RIP_RESPONSE, inFrame, inIface);
				break;
			case RIPv2.COMMAND_RESPONSE:
			{
				IPv4 ipPkt = (IPv4) inFrame.getPayload();
				UDP udpPkt = (UDP) ipPkt.getPayload();
				RIPv2 ripPkt = (RIPv2) udpPkt.getPayload();
				List<RIPv2Entry> list = ripPkt.getEntries();

				for (RIPv2Entry entry : list)
				{
					int addr = entry.getAddress();
					int mask = entry.getSubnetMask();
					int nextHop = ipPkt.getSourceAddress();
					int metric = entry.getMetric() + 1;
					if (metric > 16)
						metric = 16;

					int key = addr & mask;
					synchronized (ripEntries)
					{
						RipRecord existing = ripEntries.get(key);
						if (existing != null)
						{
							if (metric <= existing.metric)
							{
								existing.metric     = metric;
								existing.lastUpdate = System.currentTimeMillis();
								existing.nextHop    = nextHop;
								routeTable.update(addr, mask, nextHop, inIface);
							}
							if (metric == 16)
							{
								RouteEntry cur = routeTable.lookup(addr);
								if (cur != null && cur.getInterface().equals(inIface))
								{
									existing.metric = 16;
									routeTable.remove(addr, mask);
								}
							}
						}
						else
						{
							if (metric < 16)
							{
								RipRecord newRec = new RipRecord(addr, mask, nextHop,
										metric, System.currentTimeMillis());
								ripEntries.put(key, newRec);
								routeTable.insert(addr, nextHop, mask, inIface);
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

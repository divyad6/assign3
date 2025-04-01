package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;


import java.util.concurrent.ConcurrentHashMap;
import java.util.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** RIP Table for the router */
	private Map<Integer, RIPEntry> ripTable;
	
	//Constants for RIP AND ARP packets.
	private enum RIP_TYPE {
		RIP_REQUEST,
		RIP_RESPONSE,
		RIP_UNSOL
	};

	private final String MAC_BROADCAST = "ff:ff:ff:ff:ff:ff";
	private final String MAC_ZERO = "00:00:00:00:00:00";
	private final String IP_RIP_MULTICAST = "224.0.0.9";

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ripTable = new ConcurrentHashMap<>();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
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
		
		//Check what kind of packet it is and resolve the correct function.
		switch(etherPacket.getEtherType()){
			case Ethernet.TYPE_IPv4:
				IPv4 ipv4 = (IPv4)etherPacket.getPayload();
				//Check if its RIP
				if(IPv4.toIPv4Address(IP_RIP_MULTICAST) == ipv4.getDestinationAddress()){
					if(ipv4.getProtocol() == IPv4.PROTOCOL_UDP){
						UDP udp = (UDP)ipv4.getPayload();
						if(udp.getDestinationPort() == UDP.RIP_PORT){
							RIPv2 rip = (RIPv2)udp.getPayload();
							handleRIPPacket(rip.getCommand(), etherPacket, inIface);
							break;
						}
					}
				}
				//If the above fails its an IP Packet.
				handleIPPacket(etherPacket, inIface);
				break;
			default:
				break;
		}

	}

	private void handleIPPacket(Ethernet etherPacket, Iface inIface){	
		if(etherPacket.getEtherType() != Ethernet.TYPE_IPv4){
			return; //Dropped
		}

		IPv4 header = (IPv4)etherPacket.getPayload();
		short checksum = header.getChecksum();
		header = header.setChecksum((short)0);
		byte[] serial = header.serialize();
		header = (IPv4)header.deserialize(serial, 0, serial.length);

		if(checksum != header.getChecksum()){
			return; //Dropped
		}

		header = header.setTtl((byte)(header.getTtl() - 1));

		if(header.getTtl() <= 0){
			return; //Dropped
		}

		//Reserialize after changing TTL.
		header = header.setChecksum((short)0);
		serial = header.serialize();
		header = (IPv4)header.deserialize(serial, 0, serial.length);

		Ethernet packet = (Ethernet)etherPacket.setPayload(header);
		
		for(Iface inter : interfaces.values()){
			if(inter.getIpAddress() == header.getDestinationAddress()){
				return; //Dropped
			}
		}
		RouteEntry routeEntry = routeTable.lookup(header.getDestinationAddress());
		ArpEntry arpEntry = null;
		if(routeEntry == null){
			return; //Dropped
		}

		if(routeEntry.getGatewayAddress() != 0){
			arpEntry = arpCache.lookup(routeEntry.getGatewayAddress());
		}
		else{
			arpEntry = arpCache.lookup(header.getDestinationAddress());
		}

		
		MACAddress dst = arpEntry.getMac();
		MACAddress src = routeEntry.getInterface().getMacAddress();
		packet = packet.setDestinationMACAddress(dst.toBytes());
		packet = packet.setSourceMACAddress(src.toBytes());
		sendPacket(packet, routeEntry.getInterface());
	}

	//Routing Information Protocol (Local version of class that is easier to use)
	class RIPEntry {
		public int addr, mask, nextHop, dist;
		public long timestamp;

		public RIPEntry(int addr, int mask, int nextHop, int dist, long timestamp) {
			this.addr = addr;
			this.mask = mask;
			this.nextHop = nextHop;
			this.dist = dist;
			this.timestamp = timestamp;
		}	
	}
	
	//Initializes RIP tables when no predefined table is given.
	public void RIPInitialize(){
		for(Iface inter : this.interfaces.values()){
			int mask = inter.getSubnetMask();
			int addr = mask & inter.getIpAddress();
			//Insert new entry into RIP and Routing tables to be updated through DV.
			ripTable.put(addr, new RIPEntry(addr, mask, 0, 0, Integer.MIN_VALUE));
			routeTable.insert(addr, 0, mask, inter);
			//Send RIP Request.
			sendRIP(RIP_TYPE.RIP_REQUEST, null, inter);
		}

		//We need to create a task to send unsolicited RIP requests every 10 seconds now.
		TimerTask unsolicTask = new TimerTask(){
			public void run(){
				for(Iface inter : interfaces.values()){
					//SEND RIP Request
					sendRIP(RIP_TYPE.RIP_UNSOL, null, inter);
				}
			}
		};

		//We also need to timeout entries when an update hasn't been received within 30s.
		TimerTask timeoutTask = new TimerTask(){
			public void run(){
				for(RIPEntry entry : ripTable.values()){
					if(entry.timestamp >= 0 && System.currentTimeMillis() - entry.timestamp >= 30000){
						//Remove entry from the table.
						ripTable.remove(entry.addr & entry.mask);
						routeTable.remove(entry.addr, entry.mask);
					}
				}
			}
		};

		Timer timer = new Timer(true);
		timer.schedule(unsolicTask, 0, 10000);
		timer.schedule(timeoutTask, 0, 1000); //See piazza @257 for the reason why we used 1s.
	}

	private void sendRIP(RIP_TYPE type, Ethernet etherPacket, Iface iface){
		Ethernet packet = new Ethernet();
		IPv4 ipv4 = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		packet.setSourceMACAddress(iface.getMacAddress().toBytes());
		packet.setEtherType(Ethernet.TYPE_IPv4);

		ipv4.setTtl((byte)64); //Just set it arbitrarily.
		ipv4.setProtocol(IPv4.PROTOCOL_UDP);
		ipv4.setSourceAddress(iface.getIpAddress());

		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		
		//Switch based on type of RIP packet
		switch(type){
			case RIP_UNSOL:
				rip.setCommand(RIPv2.COMMAND_RESPONSE);
				packet.setDestinationMACAddress(MAC_BROADCAST);
				ipv4.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_MULTICAST));
				break;
			case RIP_REQUEST:
				rip.setCommand(RIPv2.COMMAND_REQUEST);
				packet.setDestinationMACAddress(MAC_BROADCAST);
				ipv4.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_MULTICAST));
				break;
			case RIP_RESPONSE:
				IPv4 payload = (IPv4)etherPacket.getPayload();
				rip.setCommand(RIPv2.COMMAND_RESPONSE);
				packet.setDestinationMACAddress(packet.getSourceMACAddress());
				ipv4.setDestinationAddress(payload.getSourceAddress());
				break;
			default:
				break;
		}

		//Update the tables.
		List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>();
		synchronized(ripTable){
			for(RIPEntry e : ripTable.values()){
				RIPv2Entry entry = new RIPv2Entry(e.addr, e.mask, e.dist);
				entries.add(entry);
			}
		}

		//Setup the packet payload and send out of interface.
		packet.setPayload(ipv4);
		ipv4.setPayload(udp);
		udp.setPayload(rip);
		rip.setEntries(entries);
		sendPacket(packet, iface);
	}

	//Handling the RIP Packet	
	private void handleRIPPacket(byte RIPv2Type, Ethernet packet, Iface in){
		//Based on the RIPv2 packet type, we need to forward/handle the RIP packet differently.
		switch(RIPv2Type){
			case RIPv2.COMMAND_REQUEST:
				sendRIP(RIP_TYPE.RIP_RESPONSE, packet, in);
				break;
			case RIPv2.COMMAND_RESPONSE:
				IPv4 ipv4 = (IPv4)packet.getPayload();
				UDP udp = (UDP)ipv4.getPayload();
				RIPv2 rip = (RIPv2)udp.getPayload();

				List<RIPv2Entry> entries = rip.getEntries();
				for(RIPv2Entry entry : entries){
					int addr = entry.getAddress();
					int mask = entry.getSubnetMask();
					int nextHop = ipv4.getSourceAddress();
					int dist = entry.getMetric() + 1;
					
					//Cap the metric/dist to 16 at most, this is infinity effectively.
					dist = Math.max(Integer.MIN_VALUE, Math.min(dist, 16));
					int maskedAddr = addr & mask; //Network Number
					
					//Update the RIP tables per router using the DV method.
					synchronized(ripTable){
						if(ripTable.containsKey(maskedAddr)){
							RIPEntry tableEntry = ripTable.get(maskedAddr);

							if(dist <= tableEntry.dist){
								//Only update timestamp if its better
								tableEntry.timestamp = System.currentTimeMillis();
								tableEntry.dist = dist; //Better Path!
								routeTable.update(addr, mask, nextHop, in);
							}

							//If it is "infinitely" far away.
							if(dist >= 16){
								RouteEntry currentBest = routeTable.lookup(addr);
								if(in.equals(currentBest.getInterface())){
									tableEntry.dist = 16;
									if(currentBest != null){
										routeTable.remove(addr, mask);
									}
								}
							}
						}
						else{
							//Add a new entry to the table when the node isn't known
							RIPEntry newEntry = new RIPEntry(addr, mask, nextHop, dist, System.currentTimeMillis());
							ripTable.put(maskedAddr, newEntry);
							if(dist < 16){
								//There is some path presumably.
								routeTable.insert(addr, nextHop, mask, in);
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

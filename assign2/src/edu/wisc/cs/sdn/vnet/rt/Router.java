// package edu.wisc.cs.sdn.vnet.rt;

// import java.util.*;
// import java.util.concurrent.ConcurrentHashMap;

// import edu.wisc.cs.sdn.vnet.Device;
// import edu.wisc.cs.sdn.vnet.DumpFile;
// import edu.wisc.cs.sdn.vnet.Iface;

// import net.floodlightcontroller.packet.*;

// /**
//  * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
//  */
// public class Router extends Device
// {	
// 	/** Routing table for the router */
// 	private RouteTable routeTable;
	
// 	/** ARP cache for the router */
// 	private ArpCache arpCache;

// 	// RIP table to store network entries
// 	private Map<Integer, RipEntry> ripTable;
    
//     private static final int RIP_TIMEOUT = 30000;
//     private static final int RIP_BROADCAST_INTERVAL = 10000;

//     //represents an entry in the RIP table    
// 	class RipEntry {
//         int address, mask, nextHop, metric;
//         long timestamp;
//         RipEntry(int address, int mask, int nextHop, int metric) {
//             this.address = address;
//             this.mask = mask;
//             this.nextHop = nextHop;
//             this.metric = metric;
//             this.timestamp = System.currentTimeMillis();
//         }
//     }

// 	// initialize RIP routing
// 	public void initializeRIP() {
//         for (Iface iface : this.interfaces.values()) {
// 			System.out.println("Initializing RIP on interface: " + iface.getName());
//             int network = iface.getIpAddress() & iface.getSubnetMask();
//             ripTable.put(network, new RipEntry(network, iface.getSubnetMask(), 0, 0));
//             routeTable.insert(network, 0, iface.getSubnetMask(), iface);

// 			 // Create a dummy Ethernet packet for RIP request
// 			Ethernet etherPacket = new Ethernet();
// 			etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
// 			etherPacket.setDestinationMACAddress("ff:ff:ff:ff:ff:ff"); // Broadcast MAC
// 			etherPacket.setEtherType(Ethernet.TYPE_IPv4);
			
// 			sendRIPPacket(etherPacket, RIPv2.COMMAND_REQUEST, iface);

//             //sendRIPPacket(null, RIPv2.COMMAND_REQUEST, iface);
//         }

//         Timer timer = new Timer(true);

//         timer.schedule(new TimerTask() {
//             public void run() { broadcastRIPResponses(); }
//         }, 0, RIP_BROADCAST_INTERVAL);

//         timer.schedule(new TimerTask() {
//             public void run() { removeStaleEntries(); }
//         }, 0, 1000);
//     }

// 	// process a received RIP packet
// 	private void processRIPPacket(Ethernet etherPacket, RIPv2 rip, int sourceIP, Iface inIface) {

// 		// first we get destination IP - lookup on routetable (obj routeentry)
// 		// then get subnet mask , number of hops, and next hop address
// 		// update the route table: 
// 		// if lookup returns null, we have to do an insert into routeTable 
// 		// if we do find: check if routeentry number of hops stored greater than number of hops of incoming packet
// 		// if does, update -> including timestamp
// 		// routeEntry has timestamp param -> insert/update with current time on routeTable 
// 		// when checking to remove expired entries, look to routeTable check every entry and check if routers expired. (older than 30)


// 		System.out.println("Processing RIP packet: " + rip.toString());
//         if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
//             sendRIPPacket(etherPacket, (byte) RIPv2.COMMAND_RESPONSE, inIface);
//         } else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
//             for (RIPv2Entry entry : rip.getEntries()) {
//                 int network = entry.getAddress() & entry.getSubnetMask();
//                 int newMetric = Math.min(entry.getMetric() + 1, 16);

//                 RipEntry existing = ripTable.get(network);
//                 if (existing == null || newMetric < existing.metric) {
//                     ripTable.put(network, new RipEntry(entry.getAddress(), entry.getSubnetMask(), sourceIP, newMetric));
//                     // routeTable.insert(entry.getAddress(), sourceIP, entry.getSubnetMask(), inIface);
// 					routeTable.insert(network, sourceIP, entry.getSubnetMask(), inIface); 
//                 } else {
// 					// check if old entry cost (distance) is greater than new cost
// 					routeTable.update()
// 					existing.timestamp = System.currentTimeMillis();
// 				}
//             }
//         }
//     }



// 	// remove stale RIP entries that have timed out
// 	private void removeStaleEntries() {
// 		System.out.println("remove stale entries called");
//         long currentTime = System.currentTimeMillis();
// 		ripTable.entrySet().removeIf(entry -> {
// 			if (currentTime - entry.getValue().timestamp >= RIP_TIMEOUT) {
// 				routeTable.remove(entry.getValue().address, entry.getValue().mask);
// 				return true;
// 			}
// 			return false;
// 		});
//     }
	
// 	/**
// 	 * Creates a router for a specific host.
// 	 * @param host hostname for the router
// 	 */
// 	public Router(String host, DumpFile logfile)
// 	{
// 		super(host,logfile);
// 		this.routeTable = new RouteTable();
// 		this.arpCache = new ArpCache();
// 		this.ripTable = new ConcurrentHashMap<>();
// 	}
	
// 	/**
// 	 * @return routing table for the router
// 	 */
// 	public RouteTable getRouteTable()
// 	{ return this.routeTable; }
	
// 	/**
// 	 * Load a new routing table from a file.
// 	 * @param routeTableFile the name of the file containing the routing table
// 	 */
// 	public void loadRouteTable(String routeTableFile)
// 	{
// 		if (!routeTable.load(routeTableFile, this))
// 		{
// 			System.err.println("Error setting up routing table from file "
// 					+ routeTableFile);
// 			System.exit(1);
// 		}
		
// 		System.out.println("Loaded static route table");
// 		System.out.println("-------------------------------------------------");
// 		System.out.print(this.routeTable.toString());
// 		System.out.println("-------------------------------------------------");
// 	}
	
// 	/**
// 	 * Load a new ARP cache from a file.
// 	 * @param arpCacheFile the name of the file containing the ARP cache
// 	 */
// 	public void loadArpCache(String arpCacheFile)
// 	{
// 		if (!arpCache.load(arpCacheFile))
// 		{
// 			System.err.println("Error setting up ARP cache from file "
// 					+ arpCacheFile);
// 			System.exit(1);
// 		}
		
// 		System.out.println("Loaded static ARP cache");
// 		System.out.println("----------------------------------");
// 		System.out.print(this.arpCache.toString());
// 		System.out.println("----------------------------------");
// 	}


// 	/**
// 	 * Handle an Ethernet packet received on a specific interface.
// 	 * @param etherPacket the Ethernet packet that was received
// 	 * @param inIface the interface on which the packet was received
// 	 */
// 	public void handlePacket(Ethernet etherPacket, Iface inIface)
// 	{
// 		System.out.println("*** -> Received packet: " +
// 				etherPacket.toString().replace("\n", "\n\t"));
		
// 		// ignore packets that are not IPv4
// 		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
// 			return;
// 		}

// 		// extract IPv4 header from ethernet payload
// 		IPv4 ipHeader = (IPv4) etherPacket.getPayload();

// 		// process RIP packets if needed
//         if (ipHeader.getProtocol() == IPv4.PROTOCOL_UDP) {
//             UDP udp = (UDP) ipHeader.getPayload();
//             if (udp.getDestinationPort() == UDP.RIP_PORT) {
//                 RIPv2 rip = (RIPv2) udp.getPayload();
//                 processRIPPacket(etherPacket, rip, ipHeader.getSourceAddress(), inIface);
//                 return;
//             }
//         }
	
// 		short origChecksum = ipHeader.getChecksum();

// 		// zero out checksum then recalculate by serializing/deserializing
// 		ipHeader = ipHeader.setChecksum((short) 0);
// 		byte[] ipData = ipHeader.serialize();
// 		ipHeader = (IPv4) ipHeader.deserialize(ipData, 0, ipData.length);

// 		// drop packet if checksum doesn't match
// 		if (ipHeader.getChecksum() != origChecksum) {
// 			return;
// 		}

// 		// decrement TTL and verify packet
// 		byte ttl = ipHeader.getTtl();
// 		ttl--;
// 		if (ttl <= 0) {
// 			return;
// 		}
// 		ipHeader = ipHeader.setTtl(ttl);

// 		// recalculate checksum after TTL change
// 		ipHeader = ipHeader.setChecksum((short) 0);
// 		ipData = ipHeader.serialize();
// 		ipHeader = (IPv4) ipHeader.deserialize(ipData, 0, ipData.length);

// 		// if packet's dest IP matches any of our interfaces, then drop it
// 		for (Iface iface : interfaces.values()) {
// 			if (iface.getIpAddress() == ipHeader.getDestinationAddress()) {
// 				return;
// 			}
// 		}

// 		// update ethernet packet with modified IPv4 header
// 		Ethernet outPacket = (Ethernet) etherPacket.setPayload(ipHeader);

// 		// look up the appropriate routing entry for packet's dest
// 		RouteEntry route = routeTable.lookup(ipHeader.getDestinationAddress());
// 		if (route == null) {
// 			return;
// 		}

// 		// determine the next hop - if gateway exists, use it otherwise use dest addr
// 		int nextHop = (route.getGatewayAddress() != 0) ? route.getGatewayAddress() : ipHeader.getDestinationAddress();
// 		ArpEntry arpEntry = arpCache.lookup(nextHop);
//     		if (arpEntry == null) {
// 				System.err.println("Error: ARP entry not found for next hop " + nextHop);
//         		return;
//     		}

//     		// Update MAC addresses: destination from ARP lookup and source from the outgoing interface.
//     		outPacket = outPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
//     		outPacket = outPacket.setSourceMACAddress(route.getInterface().getMacAddress().toBytes());

//     		// Forward the packet through the selected interface.
//     		sendPacket(outPacket, route.getInterface());
// 	}

// 	// send RIP packet with the specified command type
// 	private void sendRIPPacket(Ethernet etherPacket, int command, Iface outIface) {

// 		if (outIface == null) {
// 			System.err.println("Error: Output interface is null.");
// 			return;
//     	}
//         Ethernet ether = new Ethernet();
//         ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
// 		// ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
//         ether.setEtherType(Ethernet.TYPE_IPv4);

//         IPv4 ip = new IPv4();
//         ip.setTtl((byte) 64);
//         ip.setProtocol(IPv4.PROTOCOL_UDP);
//         ip.setSourceAddress(outIface.getIpAddress());
// 		// ip.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
//         // ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));

//         UDP udp = new UDP();
//         udp.setSourcePort(UDP.RIP_PORT);
//         udp.setDestinationPort(UDP.RIP_PORT);

//         RIPv2 rip = new RIPv2();

// 		if ((byte)command == RIPv2.COMMAND_REQUEST) {
// 			rip.setCommand(RIPv2.COMMAND_REQUEST);
// 			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
// 			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
// 		} else if ((byte)command == RIPv2.COMMAND_RESPONSE) {
// 			if (etherPacket != null && etherPacket.getPayload() instanceof IPv4) {
// 				// This is a direct reply to a request.
// 				IPv4 ipPacket = (IPv4)etherPacket.getPayload();
// 				rip.setCommand(RIPv2.COMMAND_RESPONSE);
// 				ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
// 				ip.setDestinationAddress(ipPacket.getSourceAddress());
// 			} else {
// 				// Unsolicited RIP response: broadcast it.
// 				rip.setCommand(RIPv2.COMMAND_RESPONSE);
// 				ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
// 				ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
// 			}
// 		}


// 		List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>();
// 		synchronized(this.ripTable)
//         {
// 			for (RipEntry localEntry : ripTable.values()) {
//             // rip.addEntry(new RIPv2Entry(entry.address, entry.mask, 0, entry.metric));
// 			RIPv2Entry entry = new RIPv2Entry(localEntry.address, localEntry.mask, localEntry.metric);
// 			entries.add(entry);
//         	}
// 		}

// 		ether.setPayload(ip);
//         ip.setPayload(udp);
//         udp.setPayload(rip);
// 		rip.setEntries(entries);

//         sendPacket(ether, outIface);
//     }

// 	// broadcast RIP responses periodically
// 	private void broadcastRIPResponses() {
// 		if (ripTable.isEmpty()) {
// 			return; // no need to send responses if there are no entries
// 		}

//         for (Iface iface : interfaces.values()) {
//             Ethernet etherPacket = new Ethernet();
// 			etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
// 			etherPacket.setDestinationMACAddress("ff:ff:ff:ff:ff:ff"); // or use the RIP multicast destination if preferred
// 			etherPacket.setEtherType(Ethernet.TYPE_IPv4);
// 			sendRIPPacket(etherPacket, RIPv2.COMMAND_RESPONSE, iface);
//         }
//     }

// }

package edu.wisc.cs.sdn.vnet.rt;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	

	class RipEntry
	{
		private int address, mask, nextHop, metric;
		private long generatedTime;
		public RipEntry(int address, int mask, int nextHop, int metric, long generatedTime) {
			this.address = address;
			this.mask = mask;
			this.nextHop = nextHop;
			this.metric = metric;
			this.generatedTime = generatedTime;
		}
	}

	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	private Map<Integer, RipEntry> ripDictionary; //Dict containing the address to object wtih metric, nextHop, generation time

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ripDictionary = new ConcurrentHashMap<Integer, RipEntry>(); //Initialize the dictionary to keep track of current and future updates of RIP records 
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
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		/********************************************************************/

		//Check packet type
		if (etherPacket.getEtherType()!=Ethernet.TYPE_IPv4){
			//drop the packet
			return;
		}

		IPv4 hdr = (IPv4) etherPacket.getPayload();

		//Check these conditions to see if the packet is an RIP packet that we need to handle
		if (hdr.getDestinationAddress()==IPv4.toIPv4Address("224.0.0.9") && hdr.getProtocol()==IPv4.PROTOCOL_UDP){
			UDP udp = (UDP) hdr.getPayload();
			if (udp.getDestinationPort() == UDP.RIP_PORT && udp.getSourcePort() == UDP.RIP_PORT ){
				RIPv2 rip = (RIPv2) udp.getPayload();
				handleRIPPacket(rip.getCommand(),etherPacket, inIface);
				return;
			}
				
		}

		short packetChecksum = hdr.getChecksum(); //grab the checksum from packet

		hdr = hdr.setChecksum((short)0); //0 out the header
		//compute the checksum by serializing and deserializing
		byte[] serialized = hdr.serialize();
		hdr = (IPv4)hdr.deserialize(serialized, 0, serialized.length);

		//if computed!=real, packet invalid, drop
		if (hdr.getChecksum()!=packetChecksum){
			return;
		}

		hdr = hdr.setTtl((byte)(hdr.getTtl()-1)); //decrement ttl by 1

		//Check the ttl
		if (hdr.getTtl()<=0){
			//drop the packet
			return;
		}

		//recompute checksum because we changed ttl
		hdr = hdr.setChecksum((short)0); //0 out the header
		serialized = hdr.serialize();
		hdr = (IPv4)hdr.deserialize(serialized, 0, serialized.length);
	
		//Check to see if the packet dest matches with ANY of our routers interfaces addresses
		for (Iface iface : interfaces.values()){
			if (iface.getIpAddress() == hdr.getDestinationAddress()){
				//we have reached, drop the packet (don't allow packets to be sent to router w/o dest)
				return;
			} 
		}

		//forward the packet otherwise 

		Ethernet newPacket = (Ethernet)etherPacket.setPayload(hdr);

		RouteEntry entry = routeTable.lookup(hdr.getDestinationAddress());
		if (entry == null) {
			return;
		}

		ArpEntry arp = null;

		//if gateway valid, we have to hop across networks, else we stay in the same network
		if (entry.getGatewayAddress() != 0) {
			arp = arpCache.lookup(entry.getGatewayAddress());
		}else {
			arp = arpCache.lookup(hdr.getDestinationAddress());
		}

		if (arp == null) {
			return;
		}

		newPacket = newPacket.setDestinationMACAddress(arp.getMac().toBytes());
		newPacket = newPacket.setSourceMACAddress(entry.getInterface().getMacAddress().toBytes());
		
		sendPacket(newPacket, entry.getInterface());
	}
	//Method to handle incoming RIP packets
	public void handleRIPPacket(byte type, Ethernet ethernetPacket, Iface inIface){

			if (type == RIPv2.COMMAND_REQUEST){
				sendRipPacket("Response", ethernetPacket, inIface);
			}
			else if (type == RIPv2.COMMAND_RESPONSE){
				IPv4 ip = (IPv4)ethernetPacket.getPayload();
				UDP udp = (UDP)ip.getPayload();
				RIPv2 rip = (RIPv2)udp.getPayload();

				List<RIPv2Entry> entries = rip.getEntries();
				for (RIPv2Entry entry : entries) 
				{
					int ipAddress = entry.getAddress();
					int mask = entry.getSubnetMask();
					int nextHop = ip.getSourceAddress();
					//increment the metric, but cap it at 16 as per RIP standard
					int metric = entry.getMetric() + 1;
					if (metric > 16) 
						metric = 16; 

					int netAddress = ipAddress & mask;

					synchronized(this.ripDictionary)
					{
						//if the address we are looking for is in the local dict
						if (ripDictionary.containsKey(netAddress))
						{
							RipEntry dictEntry = ripDictionary.get(netAddress);
							dictEntry.generatedTime = System.currentTimeMillis();

							//if the metric is less than what we have in the router, we update the routetable with the new info
							if (metric < dictEntry.metric)
							{
								dictEntry.metric = metric;

								this.routeTable.update(ipAddress, mask, nextHop, inIface);
							}
	
							if (metric >= 16) //if the metric isn't valid anymore, find the best alternate route
							{
								RouteEntry best = routeTable.lookup(ipAddress);
								if (inIface.equals(best.getInterface()))
								{
									dictEntry.metric = 16;
									if (best!=null) 
									{routeTable.remove(ipAddress, mask);}
								}
							}
						}
						else
						{
							//if the address is not in the local dictionary, then we add it to the local dictionary
							ripDictionary.put(netAddress, new RipEntry(ipAddress, mask, nextHop, metric, System.currentTimeMillis()));
							//if the calculated metric is still valid, we put it into the routetable
							if (metric < 16)
							{
								this.routeTable.insert(ipAddress, nextHop, mask, inIface);
							}
						}
					}
				}
			}
		}

	//Initialize RIP
	public void initializeRIP(){
		for (Iface iface : this.interfaces.values())
		{
			int mask = iface.getSubnetMask();
			int netAddress = mask & iface.getIpAddress();
			ripDictionary.put(netAddress, new RipEntry(netAddress, mask, 0, 0, -1));
			routeTable.insert(netAddress, 0, mask, iface);
			sendRipPacket("Request", null, iface);
		}
		//Create a task to send unsolicited response after seconds
		TimerTask sendUnsolicitedResponse = new TimerTask()
		{
			public void run()
			{
				for (Iface iface : interfaces.values())
				{ sendRipPacket("Unsolicited", null, iface); }
			}
		};
		//Create a task to time out old entries
		TimerTask timeOutOldEntries = new TimerTask()
		{
			public void run()
			{
				for (RipEntry entry : ripDictionary.values()) {
					if (entry.generatedTime != -1 && System.currentTimeMillis() - entry.generatedTime >= 30000)
					{	
						ripDictionary.remove(entry.address & entry.mask);
						routeTable.remove(entry.address, entry.mask);
					}
				}
			}
		};

		//schedule the tasks
		Timer timer = new Timer(true);
		timer.schedule(sendUnsolicitedResponse, 0, 10000); //every 10 seconds, send unsolicited response
		timer.schedule(timeOutOldEntries, 0, 1000); //every one second, check for a table entry timeout
	}
	//Method to send an rip packet
	public void sendRipPacket(String type, Ethernet ethernetPacket, Iface iface){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		//setup ethernet packet
		ether.setSourceMACAddress(iface.getMacAddress().toBytes());
		ether.setEtherType(Ethernet.TYPE_IPv4);

		//setup ip part of packet
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(iface.getIpAddress());
		
		//encapsulate in udp packet with src_port=dst_port=520
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		if (type=="Unsolicited"){ //Broadcast to all MAC's and use multicast IP
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		}else if (type == "Request"){ //Broadcast to all MAC's and use multicast IP
			rip.setCommand(RIPv2.COMMAND_REQUEST);
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		}else if (type=="Response"){ //Send back the response so set src and dest appropriately
			IPv4 ipPacket = (IPv4)ethernetPacket.getPayload();
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			ether.setDestinationMACAddress(ether.getSourceMACAddress());
			ip.setDestinationAddress(ipPacket.getSourceAddress());
		}

			List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>();
			synchronized(this.ripDictionary)
			{
				for (RipEntry localEntry : ripDictionary.values())
				{
					RIPv2Entry entry = new RIPv2Entry(localEntry.address, localEntry.mask, localEntry.metric);
					entries.add(entry);
				}
			}

			//setup payloads correctly to encapsulate the packet info
			ether.setPayload(ip);
			ip.setPayload(udp);
			udp.setPayload(rip);
			rip.setEntries(entries);

			sendPacket(ether, iface);
		}
	}


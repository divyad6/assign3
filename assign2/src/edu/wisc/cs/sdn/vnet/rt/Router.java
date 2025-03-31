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


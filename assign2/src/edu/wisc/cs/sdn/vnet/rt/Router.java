package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;

import net.floodlightcontroller.packet.IPv4;

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
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
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
		
		// ignore packets that are not IPv4
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// extract IPv4 header from ethernet payload
		IPv4 ipHeader = (IPv4) etherPacket.getPayload();
		short origChecksum = ipHeader.getChecksum();

		// zero out checksum then recalculate by serializing/deserializing
		ipHeader = ipHeader.setChecksum((short) 0);
		byte[] ipData = ipHeader.serialize();
		ipHeader = (IPv4) ipHeader.deserialize(ipData, 0, ipData.length);

		// drop packet if checksum doesn't match
		if (ipHeader.getChecksum() != origChecksum) {
			return;
		}

		// decrement TTL and verify packet
		byte ttl = ipHeader.getTtl();
		ttl--;
		if (ttl <= 0) {
			return;
		}
		ipHeader = ipHeader.setTtl(ttl);

		// recalculate checksum after TTL change
		ipHeader = ipHeader.setChecksum((short) 0);
		ipData = ipHeader.serialize();
		ipHeader = (IPv4) ipHeader.deserialize(ipData, 0, ipData.length);

		// if packet's dest IP matches any of our interfaces, then drop it
		for (Iface iface : interfaces.values()) {
			if (iface.getIpAddress() == ipHeader.getDestinationAddress()) {
				return;
			}
		}

		// update ethernet packet with modified IPv4 header
		Ethernet outPacket = (Ethernet) etherPacket.setPayload(ipHeader);

		// look up the appropriate routing entry for packet's dest
		RouteEntry route = routeTable.lookup(ipHeader.getDestinationAddress());
		if (route == null) {
			return;
		}

		// determine the next hop - if gateway exists, use it otherwise use dest addr
		int nextHop = (route.getGatewayAddress() != 0) ? route.getGatewayAddress() : ipHeader.getDestinationAddress();
		ArpEntry arpEntry = arpCache.lookup(nextHop);
    		if (arpEntry == null) {
        		return;
    		}

    		// Update MAC addresses: destination from ARP lookup and source from the outgoing interface.
    		outPacket = outPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
    		outPacket = outPacket.setSourceMACAddress(route.getInterface().getMacAddress().toBytes());

    		// Forward the packet through the selected interface.
    		sendPacket(outPacket, route.getInterface());
	}
}


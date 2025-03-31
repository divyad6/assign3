package edu.wisc.cs.sdn.vnet.rt;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	// RIP table to store network entries
	private Map<Integer, RipEntry> ripTable;
    
    private static final int RIP_TIMEOUT = 30000;
    private static final int RIP_BROADCAST_INTERVAL = 10000;

    //represents an entry in the RIP table    
	class RipEntry {
        int address, mask, nextHop, metric;
        long timestamp;
        RipEntry(int address, int mask, int nextHop, int metric) {
            this.address = address;
            this.mask = mask;
            this.nextHop = nextHop;
            this.metric = metric;
            this.timestamp = System.currentTimeMillis();
        }
    }

	// initialize RIP routing
	public void initializeRIP() {
        for (Iface iface : this.interfaces.values()) {
            int network = iface.getIpAddress() & iface.getSubnetMask();
            ripTable.put(network, new RipEntry(network, iface.getSubnetMask(), 0, 0));
            routeTable.insert(network, 0, iface.getSubnetMask(), iface);
            sendRIPPacket(RIPv2.COMMAND_REQUEST, iface);
        }

        Timer timer = new Timer(true);
        timer.schedule(new TimerTask() {
            public void run() { broadcastRIPResponses(); }
        }, 0, RIP_BROADCAST_INTERVAL);
        timer.schedule(new TimerTask() {
            public void run() { removeStaleEntries(); }
        }, 0, 1000);
    }

	// process a received RIP packet
	private void processRIPPacket(RIPv2 rip, int sourceIP, Iface inIface) {
        if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
            sendRIPPacket((byte) RIPv2.COMMAND_RESPONSE, inIface);
        } else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
            for (RIPv2Entry entry : rip.getEntries()) {
                int network = entry.getAddress() & entry.getSubnetMask();
                int newMetric = Math.min(entry.getMetric() + 1, 16);

                RipEntry existing = ripTable.get(network);
                if (existing == null || newMetric < existing.metric) {
                    ripTable.put(network, new RipEntry(entry.getAddress(), entry.getSubnetMask(), sourceIP, newMetric));
                    routeTable.insert(entry.getAddress(), sourceIP, entry.getSubnetMask(), inIface);
                }
            }
        }
    }

	// remove stale RIP entries that have timed out
	private void removeStaleEntries() {
        long currentTime = System.currentTimeMillis();
		ripTable.entrySet().removeIf(entry -> {
			if (currentTime - entry.getValue().timestamp >= RIP_TIMEOUT) {
				routeTable.remove(entry.getValue().address, entry.getValue().mask);
				return true;
			}
			return false;
		});
    }
	
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
		
		// ignore packets that are not IPv4
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// extract IPv4 header from ethernet payload
		IPv4 ipHeader = (IPv4) etherPacket.getPayload();

		// process RIP packets if needed
        if (ipHeader.getProtocol() == IPv4.PROTOCOL_UDP) {
            UDP udp = (UDP) ipHeader.getPayload();
            if (udp.getDestinationPort() == UDP.RIP_PORT) {
                RIPv2 rip = (RIPv2) udp.getPayload();
                processRIPPacket(rip, ipHeader.getSourceAddress(), inIface);
                return;
            }
        }
	
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

	// send RIP packet with the specified command type
	private void sendRIPPacket(int command, Iface outIface) {
        Ethernet ether = new Ethernet();
        ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		// ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
        ether.setEtherType(Ethernet.TYPE_IPv4);

        IPv4 ip = new IPv4();
        ip.setTtl((byte) 64);
        ip.setProtocol(IPv4.PROTOCOL_UDP);
        ip.setSourceAddress(outIface.getIpAddress());
		// ip.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
        // ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));

        UDP udp = new UDP();
        udp.setSourcePort(UDP.RIP_PORT);
        udp.setDestinationPort(UDP.RIP_PORT);

        RIPv2 rip = new RIPv2();

		if ((byte)command == RIPv2.COMMAND_REQUEST) {
			rip.setCommand(RIPv2.COMMAND_REQUEST);
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		} else if ((byte)command == RIPv2.COMMAND_RESPONSE) {
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			ether.setDestinationMACAddress(ether.getSourceMACAddress());
			ip.setDestinationAddress(ipPacket.getSourceAddress());
		}

		List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>();
		synchronized(this.ripTable)
        {
			for (RipEntry localEntry : ripTable.values()) {
            // rip.addEntry(new RIPv2Entry(entry.address, entry.mask, 0, entry.metric));
			RIPv2Entry entry = new RIPv2Entry(localEntry.address, localEntry.mask, localEntry.metric);
			entries.add(entry);
        	}
		}

		ether.setPayload(ip);
        ip.setPayload(udp);
        udp.setPayload(rip);
		rip.setEntries(entries);

        sendPacket(ether, outIface);
    }

	// broadcast RIP responses periodically
	private void broadcastRIPResponses() {
        for (Iface iface : interfaces.values()) {
            sendRIPPacket(RIPv2.COMMAND_RESPONSE, iface);
        }
    }

}


// package edu.wisc.cs.sdn.vnet.rt;

<<<<<<< HEAD
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
//             int network = iface.getIpAddress() & iface.getSubnetMask();
//             ripTable.put(network, new RipEntry(network, iface.getSubnetMask(), 0, 0));
//             routeTable.insert(network, 0, iface.getSubnetMask(), iface);
//             sendRIPPacket(RIPv2.COMMAND_REQUEST, iface);
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
// 	private void processRIPPacket(RIPv2 rip, int sourceIP, Iface inIface) {
//         if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
//             sendRIPPacket((byte) RIPv2.COMMAND_RESPONSE, inIface);
//         } else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
//             for (RIPv2Entry entry : rip.getEntries()) {
//                 int network = entry.getAddress() & entry.getSubnetMask();
//                 int newMetric = Math.min(entry.getMetric() + 1, 16);

//                 RipEntry existing = ripTable.get(network);
//                 if (existing == null || newMetric < existing.metric) {
//                     ripTable.put(network, new RipEntry(entry.getAddress(), entry.getSubnetMask(), sourceIP, newMetric));
//                     routeTable.insert(entry.getAddress(), sourceIP, entry.getSubnetMask(), inIface);
//                 }
//             }
//         }
//     }

// 	// remove stale RIP entries that have timed out
// 	private void removeStaleEntries() {
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
//                 processRIPPacket(rip, ipHeader.getSourceAddress(), inIface);
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
//         		return;
//     		}

//     		// Update MAC addresses: destination from ARP lookup and source from the outgoing interface.
//     		outPacket = outPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
//     		outPacket = outPacket.setSourceMACAddress(route.getInterface().getMacAddress().toBytes());

//     		// Forward the packet through the selected interface.
//     		sendPacket(outPacket, route.getInterface());
// 	}

// 	// send RIP packet with the specified command type
// 	private void sendRIPPacket(int command, Iface outIface) {
//         Ethernet ether = new Ethernet();
//         ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
//         ether.setEtherType(Ethernet.TYPE_IPv4);

//         IPv4 ip = new IPv4();
//         ip.setTtl((byte) 64);
//         ip.setProtocol(IPv4.PROTOCOL_UDP);
//         ip.setSourceAddress(outIface.getIpAddress());
//         ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));

//         UDP udp = new UDP();
//         udp.setSourcePort(UDP.RIP_PORT);
//         udp.setDestinationPort(UDP.RIP_PORT);

//         RIPv2 rip = new RIPv2();
//         rip.setCommand((byte)command);
//         for (RipEntry entry : ripTable.values()) {
//             rip.addEntry(new RIPv2Entry(entry.address, entry.mask, entry.metric));
//         }

//         ether.setPayload(ip);
//         ip.setPayload(udp);
//         udp.setPayload(rip);
//         sendPacket(ether, outIface);
//     }

// 	// broadcast RIP responses periodically
// 	private void broadcastRIPResponses() {
//         for (Iface iface : interfaces.values()) {
//             sendRIPPacket(RIPv2.COMMAND_RESPONSE, iface);
//         }
//     }

// }

package edu.wisc.cs.sdn.vnet.rt;
=======
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Timer;
import java.util.TimerTask;
>>>>>>> dc14f6f3328b56a1d66243a26b087056f89a828e

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.MACAddress;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author 
 *   Aaron Gember-Jacobson and 
 *   Anubhavnidhi Abhashkumar
 */
<<<<<<< HEAD
public class Router extends Device {
    
    private RouteTable routeTable;
    private ArpCache arpCache;
    private final Map<Integer, RIPEntry> ripTable;
    
    private static final String MAC_BROADCAST = "ff:ff:ff:ff:ff:ff";
    private static final String IP_RIP_MULTICAST = "224.0.0.9";
    
    public Router(String host, DumpFile logfile) {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
        this.ripTable = new ConcurrentHashMap<>();
    }
    
    public RouteTable getRouteTable() {
        return this.routeTable;
    }
    
    public void loadRouteTable(String routeTableFile) {
        if (!routeTable.load(routeTableFile, this)) {
            System.err.println("Error setting up routing table from file " + routeTableFile);
            System.exit(1);
        }
        System.out.println("Loaded static route table\n" + routeTable);
    }
    
    public void loadArpCache(String arpCacheFile) {
        if (!arpCache.load(arpCacheFile)) {
            System.err.println("Error setting up ARP cache from file " + arpCacheFile);
            System.exit(1);
        }
        System.out.println("Loaded static ARP cache\n" + arpCache);
    }
    
    public void handlePacket(Ethernet etherPacket, Iface inIface) {
        System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));
        switch (etherPacket.getEtherType()) {
            case Ethernet.TYPE_IPv4:
                handleIPv4Packet(etherPacket, inIface);
                break;
            default:
                break;
        }
    }
    
    private void handleIPv4Packet(Ethernet etherPacket, Iface inIface) {
        IPv4 ipv4 = (IPv4) etherPacket.getPayload();
        if (IPv4.toIPv4Address(IP_RIP_MULTICAST) == ipv4.getDestinationAddress()) {
            handleRIPPacket(etherPacket, inIface);
            return;
        }
        forwardIPPacket(etherPacket, inIface);
    }
    
    private void forwardIPPacket(Ethernet etherPacket, Iface inIface) {
        IPv4 ipHeader = (IPv4) etherPacket.getPayload();
        ipHeader.setTtl((byte) (ipHeader.getTtl() - 1));
        if (ipHeader.getTtl() <= 0) return;
        ipHeader.resetChecksum();
        RouteEntry route = routeTable.lookup(ipHeader.getDestinationAddress());
        if (route == null) return;
        ArpEntry arpEntry = arpCache.lookup(route.getGatewayAddress() != 0 ? route.getGatewayAddress() : ipHeader.getDestinationAddress());
        if (arpEntry == null) return;
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        etherPacket.setSourceMACAddress(route.getInterface().getMacAddress().toBytes());
        sendPacket(etherPacket, route.getInterface());
    }
    
    private void handleRIPPacket(Ethernet etherPacket, Iface inIface) {
        IPv4 ipPayload = (IPv4) etherPacket.getPayload();
        UDP udpPayload = (UDP) ipPayload.getPayload();
        RIPv2 ripPayload = (RIPv2) udpPayload.getPayload();
        processRIPEntries(ripPayload.getEntries(), ipPayload.getSourceAddress(), inIface);
    }
    
    private void processRIPEntries(List<RIPv2Entry> entries, int sourceIP, Iface inIface) {
        for (RIPv2Entry entry : entries) {
            int networkAddr = entry.getAddress() & entry.getSubnetMask();
            int metric = Math.min(entry.getMetric() + 1, 16);
            ripTable.compute(networkAddr, (key, existing) -> {
                if (existing == null || metric < existing.metric) {
                    routeTable.insert(entry.getAddress(), sourceIP, entry.getSubnetMask(), inIface);
                    return new RIPEntry(entry.getAddress(), entry.getSubnetMask(), sourceIP, metric, System.currentTimeMillis());
                }
                return existing;
            });
        }
    }
    
    private void sendRIPPacket(RIPType type, Iface iface) {
        Ethernet eth = new Ethernet();
        IPv4 ip = new IPv4();
        UDP udp = new UDP();
        RIPv2 rip = new RIPv2();
        eth.setEtherType(Ethernet.TYPE_IPv4).setSourceMACAddress(iface.getMacAddress().toBytes());
        ip.setTtl((byte) 64).setProtocol(IPv4.PROTOCOL_UDP).setSourceAddress(iface.getIpAddress());
        udp.setSourcePort(UDP.RIP_PORT).setDestinationPort(UDP.RIP_PORT);
        rip.setCommand(type == RIPType.REQUEST ? RIPv2.COMMAND_REQUEST : RIPv2.COMMAND_RESPONSE);
        rip.setEntries(getRIPEntries());
        ip.setPayload(udp.setPayload(rip));
        eth.setPayload(ip);
        sendPacket(eth, iface);
    }
    
    private List<RIPv2Entry> getRIPEntries() {
        List<RIPv2Entry> entries = new ArrayList<>();
        ripTable.values().forEach(entry -> entries.add(new RIPv2Entry(entry.addr, entry.mask, entry.metric)));
        return entries;
    }
    
    private enum RIPType { REQUEST, RESPONSE }
    
    private static class RIPEntry {
        int addr, mask, nextHop, metric;
        long timestamp;
        RIPEntry(int addr, int mask, int nextHop, int metric, long timestamp) {
            this.addr = addr;
            this.mask = mask;
            this.nextHop = nextHop;
            this.metric = metric;
            this.timestamp = timestamp;
        }
    }
=======
public class Router extends Device
{   
    /** Routing table for the router */
    private RouteTable routeTable;
    
    /** ARP cache for the router */
    private ArpCache arpCache;

    // We'll keep track of RIP info in a structure like the original code
    private Map<Integer, RipItem> ripMap;

    /**
     * Simple container for RIP data
     */
    private class RipItem
    {
        private int address;
        private int mask;
        private int nextHop;
        private int metric;
        private long timeCreated;
        
        public RipItem(int address, int mask, int nextHop, int metric, long time)
        {
            this.address    = address;
            this.mask       = mask;
            this.nextHop    = nextHop;
            this.metric     = metric;
            this.timeCreated= time;
        }
    }
    
    /**
     * Creates a router for a specific host.
     * @param host hostname for the router
     */
    public Router(String host, DumpFile logfile)
    {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache   = new ArpCache();
        this.ripMap     = new ConcurrentHashMap<>();
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
        System.out.println("*** -> Received packet: " 
            + etherPacket.toString().replace("\n", "\n\t"));
        
        /********************************************************************/
        /* TODO: Handle packets                                             */
        /********************************************************************/

        // 1) Check if it's IPv4
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
        {
            // Not IPv4, drop it
            return;
        }

        // 2) Grab IPv4 header
        IPv4 ipPacket = (IPv4) etherPacket.getPayload();

        // 3) If it's a RIP packet (multicast 224.0.0.9, UDP port 520),
        //    handle separately
        if ( (ipPacket.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9"))
             && (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) )
        {
            UDP udpPacket = (UDP) ipPacket.getPayload();
            if (udpPacket.getDestinationPort() == UDP.RIP_PORT 
                && udpPacket.getSourcePort() == UDP.RIP_PORT)
            {
                RIPv2 ripPayload = (RIPv2) udpPacket.getPayload();
                processRipPacket(ripPayload, etherPacket, inIface);
                return;
            }
        }

        // 4) Validate checksum
        short origCsum = ipPacket.getChecksum();
        ipPacket.setChecksum((short)0);
        byte[] serialized = ipPacket.serialize();
        ipPacket = (IPv4) ipPacket.deserialize(serialized, 0, serialized.length);
        if (ipPacket.getChecksum() != origCsum)
        {
            // Invalid checksum, drop
            return;
        }

        // 5) Decrement TTL, check for 0
        byte ttl = (byte) (ipPacket.getTtl() - 1);
        ipPacket.setTtl(ttl);
        if (ttl <= 0)
        {
            // TTL expired, drop
            return;
        }

        // Recompute checksum after TTL change
        ipPacket.setChecksum((short)0);
        byte[] newData = ipPacket.serialize();
        ipPacket = (IPv4) ipPacket.deserialize(newData, 0, newData.length);

        // 6) Check if packet is destined for one of our interfaces
        for (Iface routerIface : this.interfaces.values())
        {
            if (routerIface.getIpAddress() == ipPacket.getDestinationAddress())
            {
                // It's for us. We do not forward packets to our router
                return;
            }
        }

        // 7) Forward if we have an entry in our route table
        RouteEntry bestMatch = this.routeTable.lookup(ipPacket.getDestinationAddress());
        if (bestMatch == null)
        {
            // No route found, drop
            return;
        }

        // 8) Determine next-hop IP for ARP
        int nextHop = bestMatch.getGatewayAddress();
        if (nextHop == 0)
        {
            // Same subnet
            nextHop = ipPacket.getDestinationAddress();
        }

        // 9) Lookup in ARP cache
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (arpEntry == null)
        {
            // Not in ARP cache; in a real implementation we would
            // queue it and do ARP requests. For now, drop.
            return;
        }

        // 10) Update Ethernet header
        etherPacket.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

        // 11) Set the new payload with our updated IP
        etherPacket.setPayload(ipPacket);

        // 12) Send
        sendPacket(etherPacket, bestMatch.getInterface());
    }

    /**
     * Process RIP packet logic. 
     */
    private void processRipPacket(RIPv2 rip, Ethernet originalEther, Iface inIface)
    {
        if (rip.getCommand() == RIPv2.COMMAND_REQUEST)
        {
            // On a Request, we send a response
            dispatchRipPacket(RIPv2.COMMAND_RESPONSE, originalEther, inIface, false);
        }
        else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE)
        {
            IPv4 ip = (IPv4) originalEther.getPayload();
            UDP udp = (UDP) ip.getPayload();
            List<RIPv2Entry> ripEntries = rip.getEntries();
            for (RIPv2Entry entry : ripEntries)
            {
                int netIp     = entry.getAddress();
                int netMask   = entry.getSubnetMask();
                int fromIP    = ip.getSourceAddress();
                int newMetric = entry.getMetric() + 1;
                if (newMetric > 16) { newMetric = 16; }
                
                int netAddr = netIp & netMask;
                
                // Insert or update in our local map
                synchronized (this.ripMap)
                {
                    if (ripMap.containsKey(netAddr))
                    {
                        RipItem existing = ripMap.get(netAddr);
                        existing.timeCreated = System.currentTimeMillis();
                        if (newMetric < existing.metric)
                        {
                            existing.metric  = newMetric;
                            existing.nextHop = fromIP;
                            // Also update the route table if <16
                            if (newMetric < 16)
                            {
                                routeTable.update(netIp, netMask, fromIP, inIface);
                            }
                        }
                        if (newMetric >= 16)
                        {
                            // Possibly mark unreachable or remove
                            RouteEntry check = routeTable.lookup(netIp);
                            if (check != null && check.getInterface() == inIface)
                            {
                                existing.metric = 16;
                                routeTable.remove(netIp, netMask);
                            }
                        }
                    }
                    else
                    {
                        // Not present
                        RipItem newRip = new RipItem(netIp, netMask, fromIP, newMetric, System.currentTimeMillis());
                        ripMap.put(netAddr, newRip);
                        if (newMetric < 16)
                        {
                            routeTable.insert(netIp, fromIP, netMask, inIface);
                        }
                    }
                }
            }
        }
    }

    /**
     * Send out a RIP packet (response/request).
     * If 'unsolicited' is true, we do a broadcast-like approach.
     */
    private void dispatchRipPacket(byte command, Ethernet etherIn, Iface outIface, boolean unsolicited)
    {
        // Build Ethernet
        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_IPv4);
        ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
        
        // If unsolicited or request, we do a broadcast
        if (unsolicited || command == RIPv2.COMMAND_REQUEST)
        {
            ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
        }
        else
        {
            // For normal Response, we reply to the sender
            ether.setDestinationMACAddress(etherIn.getSourceMACAddress());
        }

        // Build IP
        IPv4 ip = new IPv4();
        ip.setTtl((byte) 64);
        ip.setProtocol(IPv4.PROTOCOL_UDP);
        ip.setSourceAddress(outIface.getIpAddress());
        
        if (unsolicited || command == RIPv2.COMMAND_REQUEST)
        {
            ip.setDestinationAddress("224.0.0.9"); 
        }
        else
        {
            // normal response directly to the source
            IPv4 ipIn = (IPv4) etherIn.getPayload();
            ip.setDestinationAddress(ipIn.getSourceAddress());
        }

        // Build UDP
        UDP udp = new UDP();
        udp.setSourcePort(UDP.RIP_PORT);
        udp.setDestinationPort(UDP.RIP_PORT);
        
        // Build RIP
        RIPv2 rip = new RIPv2();
        rip.setCommand(command);

        // Gather local entries
        List<RIPv2Entry> ripEntries = new ArrayList<>();
        synchronized (this.ripMap)
        {
            for (RipItem item : ripMap.values())
            {
                RIPv2Entry re = new RIPv2Entry(item.address, item.mask, item.metric);
                ripEntries.add(re);
            }
        }
        rip.setEntries(ripEntries);

        // Nest everything
        ether.setPayload(ip);
        ip.setPayload(udp);
        udp.setPayload(rip);
        
        // Send
        sendPacket(ether, outIface);
    }

    /**
     * Initialize RIP by sending a request on all interfaces and 
     * scheduling tasks for periodic updates.
     */
    public void initializeRIP()
    {
        // For each interface, add a local (connected) route + send request
        for (Iface intf : this.interfaces.values())
        {
            int myMask = intf.getSubnetMask();
            int netAddr = myMask & intf.getIpAddress();

            RipItem localEntry = new RipItem(netAddr, myMask, 0, 0, -1);
            ripMap.put(netAddr, localEntry);

            // Insert into route table
            routeTable.insert(netAddr, 0, myMask, intf);

            // Send RIP request
            dispatchRipPacket(RIPv2.COMMAND_REQUEST, null, intf, false);
        }

        // Periodic tasks
        TimerTask sendPeriodicRips = new TimerTask()
        {
            public void run()
            {
                for (Iface intf : interfaces.values())
                {
                    // Unsolicited responses
                    dispatchRipPacket(RIPv2.COMMAND_RESPONSE, null, intf, true);
                }
            }
        };

        TimerTask clearOldEntries = new TimerTask()
        {
            public void run()
            {
                synchronized (ripMap)
                {
                    List<Integer> toRemove = new ArrayList<>();
                    for (Map.Entry<Integer, RipItem> e : ripMap.entrySet())
                    {
                        RipItem val = e.getValue();
                        if (val.timeCreated == -1) { 
                            // local entry, no time check
                            continue; 
                        }
                        // If older than 30s, remove from table
                        if (System.currentTimeMillis() - val.timeCreated >= 30000)
                        {
                            toRemove.add(e.getKey());
                            routeTable.remove(val.address, val.mask);
                        }
                    }
                    for (Integer k : toRemove)
                    {
                        ripMap.remove(k);
                    }
                }
            }
        };

        Timer timer = new Timer(true);
        // Send unsolicited response every 10 seconds
        timer.schedule(sendPeriodicRips, 0, 10000);
        // Check for old entries every 1 second
        timer.schedule(clearOldEntries, 0, 30000);
    }
>>>>>>> dc14f6f3328b56a1d66243a26b087056f89a828e
}
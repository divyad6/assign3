package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
    private RouteTable routeTable;
    private ArpCache arpCache;
    private Map<Integer, RIPEntry> ripTable;

    private enum RIP_TYPE {
        RIP_REQUEST, RIP_RESPONSE, RIP_UNSOL
    }

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
        if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4) {
            IPv4 ipv4 = (IPv4) etherPacket.getPayload();
            if (IPv4.toIPv4Address(IP_RIP_MULTICAST) == ipv4.getDestinationAddress()) {
                if (ipv4.getProtocol() == IPv4.PROTOCOL_UDP) {
                    UDP udp = (UDP) ipv4.getPayload();
                    if (udp.getDestinationPort() == UDP.RIP_PORT) {
                        RIPv2 rip = (RIPv2) udp.getPayload();
                        handleRIPPacket(rip.getCommand(), etherPacket, inIface);
                        return;
                    }
                }
            }
            handleIPPacket(etherPacket, inIface);
        }
    }

    private void handleRIPPacket(byte ripCommand, Ethernet packet, Iface inIface) {
        switch (ripCommand) {
            case RIPv2.COMMAND_REQUEST:
                sendRIP(RIP_TYPE.RIP_RESPONSE, packet, inIface);
                break;
            case RIPv2.COMMAND_RESPONSE:
                IPv4 ipv4 = (IPv4) packet.getPayload();
                UDP udp = (UDP) ipv4.getPayload();
                RIPv2 rip = (RIPv2) udp.getPayload();
                
                for (RIPv2Entry entry : rip.getEntries()) {
                    int addr = entry.getAddress();
                    int mask = entry.getSubnetMask();
                    int nextHop = ipv4.getSourceAddress();
                    int dist = Math.min(entry.getMetric() + 1, 16);
                    
                    ripTable.compute(addr & mask, (key, existingEntry) -> {
                        if (existingEntry == null || dist < existingEntry.dist) {
                            routeTable.insert(addr, nextHop, mask, inIface);
                            return new RIPEntry(addr, mask, nextHop, dist, System.currentTimeMillis());
                        }
                        return existingEntry;
                    });
                }
                break;
        }
    }

    private void handleIPPacket(Ethernet etherPacket, Iface inIface) {
        IPv4 header = (IPv4) etherPacket.getPayload();
        header.setTtl((byte) (header.getTtl() - 1));
        if (header.getTtl() <= 0) return;
        header.resetChecksum();

        RouteEntry routeEntry = routeTable.lookup(header.getDestinationAddress());
        if (routeEntry == null) return;

        ArpEntry arpEntry = (routeEntry.getGatewayAddress() != 0) ?
                arpCache.lookup(routeEntry.getGatewayAddress()) :
                arpCache.lookup(header.getDestinationAddress());
        if (arpEntry == null) return;

        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());
        sendPacket(etherPacket, routeEntry.getInterface());
    }

    public void RIPInitialize() {
        for (Iface iface : this.interfaces.values()) {
            int networkAddr = iface.getIpAddress() & iface.getSubnetMask();
            ripTable.put(networkAddr, new RIPEntry(networkAddr, iface.getSubnetMask(), 0, 0, System.currentTimeMillis()));
            routeTable.insert(networkAddr, 0, iface.getSubnetMask(), iface);
            sendRIP(RIP_TYPE.RIP_REQUEST, null, iface);
        }

        Timer timer = new Timer(true);
        timer.schedule(new TimerTask() {
            public void run() {
                for (Iface iface : interfaces.values()) {
                    sendRIP(RIP_TYPE.RIP_UNSOL, null, iface);
                }
            }
        }, 0, 10000);

        timer.schedule(new TimerTask() {
            public void run() {
                ripTable.entrySet().removeIf(entry ->
                        System.currentTimeMillis() - entry.getValue().timestamp > 30000);
            }
        }, 0, 1000);
    }

    private void sendRIP(RIP_TYPE type, Ethernet etherPacket, Iface iface) {
        Ethernet packet = new Ethernet();
        IPv4 ip = new IPv4();
        UDP udp = new UDP();
        RIPv2 rip = new RIPv2();

        packet.setSourceMACAddress(iface.getMacAddress().toBytes());
        packet.setEtherType(Ethernet.TYPE_IPv4);
        ip.setTtl((byte) 64).setProtocol(IPv4.PROTOCOL_UDP).setSourceAddress(iface.getIpAddress());
        udp.setSourcePort(UDP.RIP_PORT).setDestinationPort(UDP.RIP_PORT);

        switch (type) {
            case RIP_UNSOL:
                rip.setCommand(RIPv2.COMMAND_RESPONSE);
                packet.setDestinationMACAddress(MAC_BROADCAST);
                ip.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_MULTICAST));
                break;
            case RIP_REQUEST:
                rip.setCommand(RIPv2.COMMAND_REQUEST);
                packet.setDestinationMACAddress(MAC_BROADCAST);
                ip.setDestinationAddress(IPv4.toIPv4Address(IP_RIP_MULTICAST));
                break;
            case RIP_RESPONSE:
                IPv4 payload = (IPv4) etherPacket.getPayload();
                rip.setCommand(RIPv2.COMMAND_RESPONSE);
                packet.setDestinationMACAddress(packet.getSourceMACAddress());
                ip.setDestinationAddress(payload.getSourceAddress());
                break;
        }

        ripTable.values().forEach(entry -> rip.addEntry(new RIPv2Entry(entry.addr, entry.mask, entry.dist)));
        udp.setPayload(rip);
        ip.setPayload(udp);
        packet.setPayload(ip);
        sendPacket(packet, iface);
    }

    private static class RIPEntry {
        int addr, mask, nextHop, dist;
        long timestamp;

        RIPEntry(int addr, int mask, int nextHop, int dist, long timestamp) {
            this.addr = addr;
            this.mask = mask;
            this.nextHop = nextHop;
            this.dist = dist;
            this.timestamp = timestamp;
        }
    }
}

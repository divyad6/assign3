// package edu.wisc.cs.sdn.vnet.sw;

// import net.floodlightcontroller.packet.Ethernet;
// import edu.wisc.cs.sdn.vnet.Device;
// import edu.wisc.cs.sdn.vnet.DumpFile;
// import edu.wisc.cs.sdn.vnet.Iface;

// import net.floodlightcontroller.packet.MACAddress;
// import java.util.HashMap;
// import java.util.Map;

// public class Switch extends Device
// {	
// 	private Map<MACAddress, Iface> macTable;

// 	/**
// 	 * Creates a router for a specific host.
// 	 * @param host hostname for the router
// 	 */
// 	public Switch(String host, DumpFile logfile)
// 	{
// 		super(host,logfile);
// 		macTable = new HashMap<>();
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
		
// 		/********************************************************************/
// 		/* TODO: Handle packets                                             */
		
// 		/********************************************************************/

// 		// learn or update mapping for the source MAC addr
// 		MACAddress srcMac = etherPacket.getSourceMAC();
// 		Iface currIface = macTable.get(srcMac);
// 		if (currIface == null || currIface != inIface) {
// 			macTable.put(srcMac, inIface);
// 		}

// 		// look up dest MAC addr in our table
// 		MACAddress dstMac = etherPacket.getDestinationMAC();
// 		Iface outIface = macTable.get(dstMac);

// 		// if dest interface is known, forward directly, otherwise lfood
// 		if (outIface != null) {
// 			sendPacket(etherPacket, outIface);
// 		} else {
// 			floodPacket(etherPacket, inIface);
// 		}
// 	}

// 	/**
// 	 * floods packet on all interfaces except incoming one
// 	 * @param etherPacket the ethernet packet to be flooded
// 	 * @param inIface the interface on which the packet was received
// 	 */
// 	private void floodPacket(Ethernet etherPacket, Iface inIface) {
// 		for (Iface iface : this.interfaces.values()) {
// 			if (iface != inIface) {
// 				sendPacket(etherPacket, iface);
// 			}
// 		}
// 	}
// }

package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;

import java.util.HashMap;
import java.util.Map;

import javax.lang.model.type.NullType;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	

	private Map<MACAddress, Iface> mapping; 

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		mapping = new HashMap<MACAddress, Iface>();
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
		/* TODO: Handle packets   
		 *
		                                          */
		
		/********************************************************************/

		MACAddress sourceAddr = null;
		MACAddress destAddress = null;

		//source lookup

		for (MACAddress addr: mapping.keySet()) {
			if (etherPacket.getSourceMAC().equals(addr)) {
				sourceAddr = addr;
				//interface in packet does not match table entry 
				if (!inIface.equals(mapping.get(etherPacket.getSourceMAC()))) {
					mapping.put(addr, inIface);
		
				}
			break;
			}
		}
		//ethernet source not found in table, must add it
		if (sourceAddr == null) {
			sourceAddr = etherPacket.getSourceMAC();
			mapping.put(sourceAddr, inIface);
		}

		for (MACAddress adr: mapping.keySet()) {
			if (etherPacket.getDestinationMAC().equals(adr)) {
				destAddress = adr; 
				break;
			}
		}

		//flood to all other 
		if (destAddress == null) {
			floodPackets(etherPacket, inIface);
		} else {
			//System.out.println("SENDING PACKET =========");
			this.sendPacket(etherPacket, mapping.get(destAddress));
		}

	}

	private void floodPackets(Ethernet etherPacket, Iface inIface) {

		for (Iface inter: this.interfaces.values()) {
			if (!inIface.toString().equals(inter.toString())) {
			//	System.out.println("FLOODING ===================");
				this.sendPacket(etherPacket, inter);
			}
		}

	}
}

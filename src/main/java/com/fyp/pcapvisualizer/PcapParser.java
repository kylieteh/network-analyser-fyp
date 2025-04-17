package com.fyp.pcapvisualizer;

import java.io.EOFException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

/**
 * PcapParser is responsible for reading packets from a pcap file and extracting relevant information
 * It uses the Pcap4J library to parse network traffic and stores packet details in a list
 */

public class PcapParser {
    private String pcapFile;
    private boolean isLiveCapture;
    private int interfaceIndex;

    public PcapParser(String pcapFile) {
        this.pcapFile = pcapFile;
        this.isLiveCapture = (pcapFile == null);
    }

    public PcapParser(int interfaceIndex) {
        this.isLiveCapture = true;
        this.interfaceIndex = interfaceIndex;
    }
 
    // parses packets from the pcap file and returns a list of PacketData objects
    public List<PacketData> parsePackets() throws PcapNativeException, NotOpenException {
    	
    	// creates a new List called packetList to hold packet data
        List<PacketData> packetList = new ArrayList<>();
        
        // capture live packets
		if (isLiveCapture) {
			List<PacketData> livePackets = LiveTrafficCapture.captureLivePackets(interfaceIndex);
			
			try {
				// inserts live packets into the database
				DatabaseHelper.insertPackets(livePackets);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return livePackets;
		}
        
		// if pcap file is provided, open the file
        PcapHandle handle = Pcaps.openOffline(pcapFile);

        // infinite loop to read packets until the end of the file
        while (true) {
            try {
            	// gets the next packet in the pcap file
                Packet packet = handle.getNextPacketEx();
                // gets packet timestamp
                long timestamp = handle.getTimestamp().getTime();
                // parses packet data
                PacketData packetData = parsePacket(packet, timestamp);
                // adds the packet data to the packetList
                packetList.add(packetData);

            } catch (TimeoutException e) {
                
            } catch (EOFException e) {
                break;
            }
        }
        
        try {
        	// inserts packet data into the database
            DatabaseHelper.insertPackets(packetList);
        } catch (Exception e) {
            e.printStackTrace();
        }

        handle.close();
        return packetList;
    }
    
	public static PacketData parsePacket(Packet packet, long timestamp) {
		
		// Gets packet size
		int packetSize = packet.length();
		
		// Gets packet protocol
        String protocol = "Unknown";

        if (packet.contains(TcpPacket.class)) {
            protocol = "TCP";

            // Extract TCP header and get the source/destination port
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

            // Check for HTTP or HTTPS 
            if (srcPort == 80 || dstPort == 80) {
                protocol = "HTTP";  
            } else if (srcPort == 443 || dstPort == 443) {
                protocol = "HTTPS";  
            }
            
        } else if (packet.contains(UdpPacket.class)) {
            protocol = "UDP";

            // Extract UDP header and get the source/destination port
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();

            // Check for DNS (Runs over UDP port 53)
            if (srcPort == 53 || dstPort == 53) {
                protocol = "DNS";
            }
            
        } else if (packet.contains(IcmpV4CommonPacket.class)) {
            protocol = "ICMPv4";  // IPv4 Internet Control Message Protocol
        } else if (packet.contains(IcmpV6CommonPacket.class)) {
            protocol = "ICMPv6";  // IPv6 Internet Control Message Protocol
        } else if (packet.contains(ArpPacket.class)) {
            protocol = "ARP";  // Address Resolution Protocol
        } else if (packet.contains(IpV4Packet.class)) {
            protocol = "IPv4";  // Generic IPv4 packet
        } else if (packet.contains(IpV6Packet.class)) {
            protocol = "IPv6";  // Generic IPv6 packet
        } else if (packet.contains(SctpPacket.class)) {
            protocol = "SCTP";  // Stream Control Transmission Protocol
        }

        // Gets packet source port and destination port
        Integer srcPort = null, dstPort = null;

        if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
            dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
        } else if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        }

        // Gets packet source IP and destination IP
        String srcIP = "Unknown", dstIP = "Unknown";
        
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            srcIP = ipPacket.getHeader().getSrcAddr().getHostAddress();
            dstIP = ipPacket.getHeader().getDstAddr().getHostAddress();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipPacket = packet.get(IpV6Packet.class);
            srcIP = ipPacket.getHeader().getSrcAddr().getHostAddress();
            dstIP = ipPacket.getHeader().getDstAddr().getHostAddress();
        } else if (packet.contains(ArpPacket.class)) {
            ArpPacket arpPacket = packet.get(ArpPacket.class);
            srcIP = arpPacket.getHeader().getSrcProtocolAddr().toString();
            dstIP = arpPacket.getHeader().getDstProtocolAddr().toString();
        }
        
		return new PacketData(timestamp, protocol, srcIP, srcPort, dstIP, dstPort, packetSize);
	}
}
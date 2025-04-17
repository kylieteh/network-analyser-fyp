package com.fyp.pcapvisualizer;

/**
 * Represents a network packet with timestamp, protocol, source & destination IP and source & destination port
 * This class acts as a data container for storing packet details extracted from a pcap file
 */

public class PacketData {
    private long timestamp;
    private String protocol;
    private String srcIP;
    private Integer srcPort;
    private String dstIP;
    private Integer dstPort;
    private int packetSize;

    public PacketData(long timestamp, String protocol, String srcIP, Integer srcPort, String dstIP, Integer dstPort, int packetSize) {
        this.timestamp = timestamp;
        this.protocol = protocol;
        this.srcIP = srcIP;
        this.srcPort = srcPort;
        this.dstIP = dstIP;
        this.dstPort = dstPort;
        this.packetSize = packetSize;
    }

    public long getTimestamp() { 
    	return timestamp; 
    }
    
    public String getProtocol() { 
    	return protocol; 
    }
    
    public String getSrcIP() { 
    	return srcIP; 
    }
    
    public Integer getSrcPort() {
    	return srcPort; 
    }
    
    public String getDstIP() {
    	return dstIP; 
    }
    
    public Integer getDstPort() {
    	return dstPort; 
    }
    
    public int getPacketSize() {
    	return packetSize;
    }
}

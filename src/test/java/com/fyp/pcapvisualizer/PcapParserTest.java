package com.fyp.pcapvisualizer;

import org.junit.jupiter.api.Test;
import java.io.File;
import java.net.URL;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PcapParserTest {

    @Test
    public void testParsePacketsFromPcapFile() throws Exception {
        
        URL resource = getClass().getClassLoader().getResource("test_sample.pcap");
        assertNotNull(resource, "Test PCAP file not found.");

        String testPcapPath = new File(resource.toURI()).getAbsolutePath();
        PcapParser parser = new PcapParser(testPcapPath);
        List<PacketData> packets = parser.parsePackets();

        assertFalse(packets.isEmpty());
        for (PacketData packet : packets) {
            assertNotNull(packet.getProtocol());
            assertNotNull(packet.getSrcIP());
            assertNotNull(packet.getDstIP());
        }
    }
}

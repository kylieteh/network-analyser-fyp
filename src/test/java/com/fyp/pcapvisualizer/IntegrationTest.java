package com.fyp.pcapvisualizer;

import org.junit.jupiter.api.*;
import java.util.List;
import java.sql.*;

import static org.junit.jupiter.api.Assertions.*;

public class IntegrationTest {

    private static final String TEST_SAMPLE_PATH = "src/test/resources/test_sample.pcap";

    @BeforeAll
    public static void setup() throws SQLException {
        DatabaseHelper.createTable();
    }

    @Test
    public void testPcapParsingToDatabaseIntegration() throws Exception {
        PcapParser parser = new PcapParser(TEST_SAMPLE_PATH);
        List<PacketData> packets = parser.parsePackets();

        assertFalse(packets.isEmpty(), "Parsed packet list should not be empty");

        List<PacketData> fromDb = DataProcessor.getPacketData();

        assertEquals(packets.size(), fromDb.size(), "Database should contain same number of packets");
        assertEquals(packets.get(0).getProtocol(), fromDb.get(0).getProtocol(), "Protocol should match");

        PacketData p = fromDb.get(0);
        assertNotNull(p.getSrcIP(), "Source IP should not be null");
        assertTrue(p.getPacketSize() > 0, "Packet size should be positive");
    }
}

package com.fyp.pcapvisualizer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class DatabaseHelperTest {

    @BeforeEach
    public void resetDB() throws SQLException {
        DatabaseHelper.createTable();
    }

    @Test
    public void testInsertAndReadPackets() throws SQLException {
        PacketData packet = new PacketData(
                1690000000000L,
                "UDP",
                "10.0.0.1",
                5000,
                "10.0.0.2",
                53,
                512
        );

        DatabaseHelper.insertPackets(List.of(packet));
        List<PacketData> retrieved = DataProcessor.getPacketData();

        assertEquals(1, retrieved.size());
        PacketData result = retrieved.get(0);

        assertEquals("UDP", result.getProtocol());
        assertEquals("10.0.0.1", result.getSrcIP());
        assertEquals("10.0.0.2", result.getDstIP());
        assertEquals(5000, result.getSrcPort());
        assertEquals(53, result.getDstPort());
        assertEquals(512, result.getPacketSize());
    }
}

package com.fyp.pcapvisualizer;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class PacketDataTest {

    @Test
    public void testPacketDataFields() {
        PacketData packet = new PacketData(
            1690000000000L,
            "TCP",
            "192.168.0.1",
            1234,
            "192.168.0.2",
            80,
            1500
        );

        assertEquals(1690000000000L, packet.getTimestamp());
        assertEquals("TCP", packet.getProtocol());
        assertEquals("192.168.0.1", packet.getSrcIP());
        assertEquals(1234, packet.getSrcPort());
        assertEquals("192.168.0.2", packet.getDstIP());
        assertEquals(80, packet.getDstPort());
        assertEquals(1500, packet.getPacketSize());
    }
}

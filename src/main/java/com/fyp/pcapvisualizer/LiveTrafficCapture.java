package com.fyp.pcapvisualizer;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.sql.SQLException;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;
import java.io.EOFException;
import java.util.ArrayList;

public class LiveTrafficCapture {

    private static final int SNAP_LEN = 65536; // Maximum bytes per packet
    private static final int TIMEOUT = 5000; // Timeout in milliseconds

    /**
     * Captures live network traffic and stores it in the database.
     */
    public static List<PacketData> captureLivePackets(int interfaceIndex) throws PcapNativeException, NotOpenException {
        List<PacketData> packetList = new ArrayList<>();

        // gets a list of available network interfaces
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces == null || interfaces.isEmpty()) {
            System.out.println("No network interfaces found!");
            return packetList;
        }

        // validates selected interface index
        if (interfaceIndex < 0 || interfaceIndex >= interfaces.size()) {
            System.out.println("Invalid network interface selected.");
            return packetList;
        }

        PcapNetworkInterface nif = interfaces.get(interfaceIndex);
        System.out.println("Capturing live traffic on: " + nif.getName());

        // opens a live capture handle
        PcapHandle handle = nif.openLive(
                SNAP_LEN, 
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 
                TIMEOUT
        );

        while (true) {
            try {
                Packet packet = handle.getNextPacketEx();
                long timestamp = System.currentTimeMillis(); // Use system time for live packets
                
                PacketData packetData = PcapParser.parsePacket(packet, timestamp);
                packetList.add(packetData);

                // stores in database
                DatabaseHelper.insertPackets(List.of(packetData));

                System.out.println("Captured: " + packetData.getTimestamp() + " | " + packetData.getSrcIP() + " → " + packetData.getDstIP() +
                        " | Protocol: " + packetData.getProtocol());

            } catch (TimeoutException e) {
                System.out.println("No packets received in last " + TIMEOUT + "ms...");
            } catch (EOFException e) {
                break;
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        handle.close();
        return packetList;
    }
}

package com.fyp.pcapvisualizer;

import java.sql.*;
import java.util.*;

public class DataProcessor {

    /**
     * Retrieves packet data from the database for visualization.
     * 
     */
	
	// retrieves all packets from the database and stores them in a list
    public static List<PacketData> getPacketData() throws SQLException {
        // creates a list to store packet data
    	List<PacketData> packets = new ArrayList<>();
    	// sql query to retrieve packet data
        String sql = "SELECT timestamp, protocol, src_ip, src_port, dst_ip, dst_port, packet_size FROM packets";

        // establishes connection to database
        try (Connection conn = DatabaseHelper.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

        	// iterate through each row in the result set and create PacketData object
            while (rs.next()) {
                packets.add(new PacketData(
                        rs.getLong("timestamp"),
                        rs.getString("protocol"),
                        rs.getString("src_ip"),
                        rs.getInt("src_port"),
                        rs.getString("dst_ip"),
                        rs.getInt("dst_port"),
                        rs.getInt("packet_size")
                ));
            }
        }
        // returns the list pf PacketData objects
        return packets;
    }
}

package com.fyp.pcapvisualizer;

import java.sql.*;
import java.util.List;

/**
 * DatabaseHelper is responsible for handling database operations using sqlite3
 * It provides methods to create a table, insert packet data and display stored packets
 */

public class DatabaseHelper {
	// sqlite database file path
    private static final String DB_URL = "jdbc:sqlite:sample.db";

    // establishes a connection to the sqlite database
    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    // creates a "packets" table in the sqlite database
    public static void createTable() throws SQLException {
    	String sql = "DROP TABLE IF EXISTS packets; " + // Clears old data
    				"CREATE TABLE packets (" +
    				"id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    				"timestamp INTEGER, " +
    				"protocol TEXT, " +
    				"src_ip TEXT, " +
    				"src_port INTEGER, " +
    				"dst_ip TEXT, " +
    				"dst_port INTEGER, " +
                    "packet_size INTEGER);";

    	// establish connect and execute sql statement
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        }
    }

    // inserts a list of PacketData objects into the "packets" table
    public static void insertPackets(List<PacketData> packets) throws SQLException {
    	// prepared statements used
        String sql = "INSERT INTO packets (timestamp, protocol, src_ip, src_port, dst_ip, dst_port, packet_size) VALUES (?, ?, ?, ?, ?, ?, ?)";

        // establish connection to the database
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
        	// loops through each packet in the list and adds the data into the database
        	for (PacketData packet : packets) {
                pstmt.setLong(1, packet.getTimestamp());
                pstmt.setString(2, packet.getProtocol());
                pstmt.setString(3, packet.getSrcIP());
                pstmt.setObject(4, packet.getSrcPort()); // Use setObject to allow NULL values
                pstmt.setString(5, packet.getDstIP());
                pstmt.setObject(6, packet.getDstPort());
                pstmt.setObject(7, packet.getPacketSize());
                pstmt.executeUpdate();
            }
        }
    }

    // displays all packets in the database to the console
    public static void displayPackets() throws SQLException {
        String sql = "SELECT timestamp, protocol, src_ip, src_port, dst_ip, dst_port, packet_size FROM packets";

        // establish connection to the database
        try (Connection conn = connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

        	// iterate over the result set and print packet details
        	// "timestamp | protocol | src_ip:src_port -> dst_ip:dst_port"
            while (rs.next()) {
                System.out.println(rs.getString("timestamp") + " | " + rs.getString("protocol") +
                        " | " + rs.getString("src_ip") + ":" + rs.getInt("src_port") +
                        " -> " + rs.getString("dst_ip") + ":" + rs.getInt("dst_port"));
            }
        }
    }
}

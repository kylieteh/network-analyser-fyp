package com.fyp.pcapvisualizer;

import java.sql.SQLException;

/**
 * DatabaseTest is a simple test class to verify if the sqlite database connection 
 * is successfully established
 */

public class DatabaseTest {
    public static void main(String[] args) throws SQLException {
        // attempt to connect to the database
        DatabaseHelper.connect(); // Test database connection
        System.out.println("Database connection successful.");
    }
}

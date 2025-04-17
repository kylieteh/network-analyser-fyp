package com.fyp.pcapvisualizer;

public class Main {
    public static void main(String[] args) {
        try {
            // Ensure DB table is created before launching GUI
            DatabaseHelper.createTable();
        } catch (Exception e) {
            System.err.println("Failed to initialize database:");
            e.printStackTrace();
        }

        // Start the GUI
        NetworkAnalyzerUI.main(args);
    }
}

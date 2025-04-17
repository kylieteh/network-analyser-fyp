# Network Visualiser (Final Year Project)

A Java-based desktop application for visualising network traffic captured from .pcap files or live interfaces, with dynamic graphs and an interactive UI.

## Overview
The tool allows users to:
- Upload .pcap files or capture live traffic from available network interfaces
- Store parsed packet metadata in an embedded SQLite database
- View traffic insights through five different types of visualisations

## Features
- Offline and live capture using Pcap4J
- Visualisations powered by JFreeChart and JUNG:
  - Protocol Distribution (Pie Chart)
  - Traffic Over Time (Time Series Chart)
  - Port Usage Analysis (Bar Chart)
  - Packet Size Distribution (Histogram)
  - IP-to-IP Connection Graph (Node-Edge Diagram)
- Graphical user interface built with Java Swing
- Dark/Light mode toggle using FlatLaf
- Dynamic graph refreshing
- Data stored in SQLite using JDBC

## How to Run
1. Clone the repository
   ```
   git clone https://github.com/kylieteh/network-analyser-fyp.git
    cd network-analyzer-fyp
   ```
3. Open the project in an IDE such as Eclipse or IntelliJ and ensure the following libraries are set up:
   - Pcap4J
   - JFreeChart
   - JUNG
   - FlatLaf
   - SQLite JDBC driver
4. Run Main.java to launch the GUI

## Future Improvements
- Add filtering by IP, protocol, or time
- Export charts as image files
- Pause and resume live capture
- Package the application as a standalone JAR or platform installer
- Extend support for deep packet inspection and payload analysis

## Technologies Used
- Java (SE)
- Pcap4J
- JFreeChart
- JUNG
- SQLite (via JDBC)
- Java Swing and FlatLaf

## License
This project was developed as part of an undergraduate final year project and is intended for academic use only.

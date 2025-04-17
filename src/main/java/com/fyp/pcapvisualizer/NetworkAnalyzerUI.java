// NetworkAnalyzerUI.java
package com.fyp.pcapvisualizer;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;

public class NetworkAnalyzerUI {
    private static JPanel cardPanel;
    private static CardLayout cardLayout;
    private static Map<String, JPanel> graphPanels = new HashMap<>();
    private static boolean darkMode = true;

    public static void main(String[] args) {
        setLookAndFeel();
        SwingUtilities.invokeLater(NetworkAnalyzerUI::createAndShowGUI);
    }

    private static void setLookAndFeel() {
        try {
            UIManager.setLookAndFeel(darkMode ? new FlatDarkLaf() : new FlatLightLaf());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Network Analyzer");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1200, 700);
        frame.setLayout(new BorderLayout());

        // Sidebar
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setPreferredSize(new Dimension(250, frame.getHeight()));
        sidebar.setBorder(BorderFactory.createEmptyBorder(20, 10, 20, 10));

        String[] buttons = {
            "Refresh All Graphs",
            "Toggle Dark/Light Mode",
            "Capture Live Traffic",
            "Choose Pcap File",
            "Show All Graphs",
            "Protocol Distribution Graph",
            "Network Traffic Graph",
            "Port Usage Analysis Graph",
            "Packet Size Distribution Graph",
            "Network Connection Graph"
        };

        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);
        JLabel placeholder = new JLabel("No graphs shown", SwingConstants.CENTER);
        placeholder.setFont(new Font("Arial", Font.PLAIN, 18));
        cardPanel.add(placeholder, "default");
        cardLayout.show(cardPanel, "default");

        // Load individual charts
        loadAllCharts();

        // Combined view panel
        JPanel allGraphsContent = new JPanel(new GridLayout(3, 2, 20, 20));
        allGraphsContent.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        Dimension chartPreferredSize = new Dimension(500, 300);

        JPanel protocolPanel = ChartGenerator.getProtocolDistributionPanel();
        protocolPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(protocolPanel);

        JPanel trafficPanel = ChartGenerator.getTrafficOverTimePanel();
        trafficPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(trafficPanel);

        JPanel portPanel = ChartGenerator.getPortUsageAnalysisPanel();
        portPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(portPanel);

        JPanel sizePanel = ChartGenerator.getPacketSizeDistributionPanel();
        sizePanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(sizePanel);

        JPanel connectionPanel = ChartGenerator.getConnectionGraphPanel();
        connectionPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(connectionPanel);

        JScrollPane scrollPane = new JScrollPane(allGraphsContent);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        cardPanel.add(scrollPane, "Show All Graphs");

        int[] separatorAfter = {0, 1, 3};
        for (int i = 0; i < buttons.length; i++) {
            String label = buttons[i];
            JButton button = new JButton(label);
            button.setAlignmentX(Component.CENTER_ALIGNMENT);
            button.setMaximumSize(new Dimension(200, 30));
            sidebar.add(Box.createVerticalStrut(10));
            sidebar.add(button);
            button.addActionListener(e -> onButtonClick(e, frame));

            for (int sep : separatorAfter) {
                if (i == sep) {
                    sidebar.add(Box.createVerticalStrut(15));
                    JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
                    separator.setMaximumSize(new Dimension(220, 5));
                    separator.setForeground(Color.GRAY);
                    sidebar.add(separator);
                    sidebar.add(Box.createVerticalStrut(5));
                    break;
                }
            }
        }

        frame.add(sidebar, BorderLayout.WEST);
        frame.add(cardPanel, BorderLayout.CENTER);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static void onButtonClick(ActionEvent e, JFrame frame) {
    String action = ((JButton) e.getSource()).getText();

    if ("Refresh All Graphs".equals(action)) {
        // Save current card name
        String currentCard = null;
        for (Map.Entry<String, JPanel> entry : graphPanels.entrySet()) {
            if (entry.getValue().isShowing()) {
                currentCard = entry.getKey();
                break;
            }
        }

        if (currentCard == null && cardPanel.getComponentCount() > 0) {
            for (Component comp : cardPanel.getComponents()) {
                if (comp.isShowing()) {
                    if (comp.getName() != null) {
                        currentCard = comp.getName();
                    }
                    break;
                }
            }
        }

        // Rebuild graph panels
        graphPanels.clear();
        cardPanel.removeAll();
        
        loadAllCharts();  // This adds all graphs into cardPanel via addGraphPanel()

        JPanel allGraphsContent = new JPanel(new GridLayout(3, 2, 20, 20));
        allGraphsContent.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        Dimension chartPreferredSize = new Dimension(500, 300);

        JPanel protocolPanel = ChartGenerator.getProtocolDistributionPanel();
        protocolPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(protocolPanel);

        JPanel trafficPanel = ChartGenerator.getTrafficOverTimePanel();
        trafficPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(trafficPanel);

        JPanel portPanel = ChartGenerator.getPortUsageAnalysisPanel();
        portPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(portPanel);

        JPanel sizePanel = ChartGenerator.getPacketSizeDistributionPanel();
        sizePanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(sizePanel);

        JPanel connectionPanel = ChartGenerator.getConnectionGraphPanel();
        connectionPanel.setPreferredSize(chartPreferredSize);
        allGraphsContent.add(connectionPanel);

        JScrollPane scrollPane = new JScrollPane(allGraphsContent);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);cardPanel.add(scrollPane, "Show All Graphs");

        cardPanel.revalidate();
        cardPanel.repaint();

        // Go back to same view
        if (currentCard != null) {
            cardLayout.show(cardPanel, currentCard);
        } else {
            cardLayout.show(cardPanel, "default");
        }
        return;
    }

    switch (action) {
        case "Toggle Dark/Light Mode":
            darkMode = !darkMode;
            frame.dispose();
            setLookAndFeel();
            SwingUtilities.invokeLater(NetworkAnalyzerUI::createAndShowGUI);
            break;

        case "Capture Live Traffic":
            handleLiveCapture();
            break;

        case "Choose Pcap File":
            handlePcapFileSelection();
            break;

        default:
            cardLayout.show(cardPanel, action);
            break;
    }
    }

    private static void addGraphPanel(String name, JPanel panel) {
    	panel.setName(name);
    	graphPanels.put(name, panel);
        cardPanel.add(panel, name);
    }

    private static void loadAllCharts() {
        addGraphPanel("Protocol Distribution Graph", ChartGenerator.getProtocolDistributionPanel());
        addGraphPanel("Network Traffic Graph", ChartGenerator.getTrafficOverTimePanel());
        addGraphPanel("Port Usage Analysis Graph", ChartGenerator.getPortUsageAnalysisPanel());
        addGraphPanel("Packet Size Distribution Graph", ChartGenerator.getPacketSizeDistributionPanel());
        addGraphPanel("Network Connection Graph", ChartGenerator.getConnectionGraphPanel());
    }

    private static void handleLiveCapture() {
        SwingUtilities.invokeLater(() -> {
            try {
                List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
                String[] interfaceNames = interfaces.stream()
                    .map(i -> i.getName() + " - " + i.getDescription())
                    .toArray(String[]::new);

                String selected = (String) JOptionPane.showInputDialog(
                    null,
                    "Select network interface:",
                    "Live Capture",
                    JOptionPane.PLAIN_MESSAGE,
                    null,
                    interfaceNames,
                    interfaceNames[0]
                );

                if (selected != null) {
                    int index = Arrays.asList(interfaceNames).indexOf(selected);
                    new Thread(() -> {
                        try {
                            LiveTrafficCapture.captureLivePackets(index);
                            JOptionPane.showMessageDialog(null, "Capturing started. Refresh graphs to view updated data.");
                        } catch (Exception ex) {
                            ex.printStackTrace();
                            JOptionPane.showMessageDialog(null, "Error capturing: " + ex.getMessage());
                        }
                    }).start();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(null, "Error listing interfaces: " + ex.getMessage());
            }
        });
    }

    private static void handlePcapFileSelection() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a .pcap file");
        int result = chooser.showOpenDialog(null);

        if (result == JFileChooser.APPROVE_OPTION) {
            String filePath = chooser.getSelectedFile().getAbsolutePath();
            new Thread(() -> {
                try {
                    PcapParser parser = new PcapParser(filePath);
                    java.util.List<PacketData> packets = parser.parsePackets();
                    DatabaseHelper.insertPackets(packets);
                    JOptionPane.showMessageDialog(null, "PCAP file parsed and data inserted. Refresh graphs to view updated data.");
                } catch (Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Error reading file: " + e.getMessage());
                }
            }).start();
        }
    }
}

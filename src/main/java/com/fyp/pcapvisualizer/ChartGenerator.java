package com.fyp.pcapvisualizer;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.statistics.HistogramDataset;
import org.jfree.data.time.Second;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import edu.uci.ics.jung.algorithms.layout.CircleLayout;
import edu.uci.ics.jung.graph.DirectedSparseGraph;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.DefaultModalGraphMouse;
import edu.uci.ics.jung.visualization.decorators.ToStringLabeller;

public class ChartGenerator {
    public static JPanel getProtocolDistributionPanel() {
        DefaultPieDataset dataset = new DefaultPieDataset();
        String sql = "SELECT protocol, COUNT(*) AS count FROM packets GROUP BY protocol";

        try (Connection conn = DatabaseHelper.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            boolean hasData = false;
            while (rs.next()) {
                hasData = true;
                dataset.setValue(rs.getString("protocol"), rs.getInt("count"));
            }

            if (!hasData) return createWarningPanel("No packet data available.");

        } catch (SQLException e) {
            e.printStackTrace();
            return createWarningPanel("Database error.");
        }

        JFreeChart chart = ChartFactory.createPieChart("Protocol Distribution", dataset, true, true, false);
        PiePlot plot = (PiePlot) chart.getPlot();
        plot.setLabelGenerator(new StandardPieSectionLabelGenerator(
                "{0}: {1} packets ({2})", new DecimalFormat("0"), new DecimalFormat("0.0%")));

        return new ChartPanel(chart);
    }

    public static JPanel getTrafficOverTimePanel() {
        TimeSeries series = new TimeSeries("Packets Per Second");
        String sql = "SELECT timestamp / 1000 AS second, COUNT(*) AS count FROM packets GROUP BY second ORDER BY second";

        try (Connection conn = DatabaseHelper.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                long time = rs.getLong("second") * 1000;
                series.addOrUpdate(new Second(new java.util.Date(time)), rs.getInt("count"));
            }

        } catch (SQLException e) {
            e.printStackTrace();
            return createWarningPanel("Database error.");
        }

        TimeSeriesCollection dataset = new TimeSeriesCollection(series);
        JFreeChart chart = ChartFactory.createTimeSeriesChart(
                "Network Traffic Over Time", "Time", "Packets Per Second", dataset);

        XYPlot plot = (XYPlot) chart.getPlot();
        plot.setDomainAxis(new DateAxis("Time"));

        return new ChartPanel(chart);
    }

    public static JPanel getPortUsageAnalysisPanel() {
        String sql = "SELECT src_port AS port, COUNT(*) AS packet_count FROM packets WHERE src_port IS NOT NULL GROUP BY src_port " +
                     "UNION SELECT dst_port AS port, COUNT(*) AS packet_count FROM packets WHERE dst_port IS NOT NULL GROUP BY dst_port " +
                     "ORDER BY packet_count DESC LIMIT 10";

        DefaultCategoryDataset dataset = new DefaultCategoryDataset();

        try (Connection conn = DatabaseHelper.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                dataset.addValue(rs.getInt("packet_count"), "Packets", String.valueOf(rs.getInt("port")));
            }

        } catch (SQLException e) {
            e.printStackTrace();
            return createWarningPanel("Database error.");
        }

        JFreeChart chart = ChartFactory.createBarChart(
                "Top 10 Active Ports", "Port Number", "Packet Count", dataset,
                PlotOrientation.VERTICAL, false, true, false);

        return new ChartPanel(chart);
    }

    public static JPanel getPacketSizeDistributionPanel() {
        String sql = "SELECT packet_size FROM packets WHERE packet_size IS NOT NULL";
        List<Double> sizes = new ArrayList<>();

        try (Connection conn = DatabaseHelper.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                sizes.add(rs.getDouble("packet_size"));
            }

        } catch (SQLException e) {
            e.printStackTrace();
            return createWarningPanel("Database error.");
        }

        if (sizes.isEmpty()) return createWarningPanel("No packet size data found.");

        double[] array = sizes.stream().mapToDouble(Double::doubleValue).toArray();
        HistogramDataset dataset = new HistogramDataset();
        dataset.addSeries("Packet Size", array, 10);

        JFreeChart chart = ChartFactory.createHistogram(
                "Packet Size Distribution", "Packet Size (Bytes)", "Frequency", dataset);

        return new ChartPanel(chart);
    }

    public static JPanel getConnectionGraphPanel() {
        Graph<String, String> graph = new DirectedSparseGraph<>();
        Map<String, Integer> edgeCounts = new HashMap<>();
        String sql = "SELECT src_ip, dst_ip, COUNT(*) AS packet_count FROM packets WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL GROUP BY src_ip, dst_ip";

        try (Connection conn = DatabaseHelper.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            int edgeId = 0;
            while (rs.next()) {
                String src = rs.getString("src_ip");
                String dst = rs.getString("dst_ip");
                int count = rs.getInt("packet_count");

                graph.addVertex(src);
                graph.addVertex(dst);
                String eid = "E" + edgeId++;
                graph.addEdge(eid, src, dst);
                edgeCounts.put(eid, count);
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return createWarningPanel("Database error.");
        }

        CircleLayout<String, String> layout = new CircleLayout<>(graph);
        layout.setSize(new Dimension(600, 600));
        VisualizationViewer<String, String> vv = new VisualizationViewer<>(layout);
        vv.setPreferredSize(new Dimension(650, 650));
        vv.getRenderContext().setVertexLabelTransformer(new ToStringLabeller());
        vv.getRenderContext().setEdgeLabelTransformer(edge -> edgeCounts.getOrDefault(edge, 0) + " packets");
        vv.getRenderContext().setEdgeStrokeTransformer(edge -> {
            float width = Math.min(10.0f, 1.0f + (float) Math.log(edgeCounts.getOrDefault(edge, 1)));
            return new BasicStroke(width);
        });

        vv.setGraphMouse(new DefaultModalGraphMouse<>());
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(vv, BorderLayout.CENTER);
        return panel;
    }

    private static JPanel createWarningPanel(String message) {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel label = new JLabel(message, SwingConstants.CENTER);
        label.setForeground(Color.RED);
        panel.add(label, BorderLayout.CENTER);
        return panel;
    }
}
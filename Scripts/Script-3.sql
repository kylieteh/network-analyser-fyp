SELECT timestamp, protocol, src_ip, src_port, dst_ip, dst_port 
FROM packets
ORDER BY timestamp;

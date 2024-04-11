import dpkt
import socket
from collections import Counter
import csv
import os
from datetime import datetime

def detect_network_scan(pcap_files, output_csv_dir):
    MIN_DESTINATIONS = 40
    RATE_THRESHOLD = 0

    start_time = datetime.now()
    print(f"Script started at: {start_time}")

    generated_csv_files = []

    for pcap_file in pcap_files:
        packet_data = {}

        with open(pcap_file, 'rb') as file:
            pcap = dpkt.pcap.Reader(file)
            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)

                    dst_network = '.'.join(dst_ip.split('.')[:1]) + 'x.x.x/24'

                    if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                        dst_port = ip.data.dport

                        if src_ip not in packet_data:
                            packet_data[src_ip] = {}
                        if dst_network not in packet_data[src_ip]:
                            packet_data[src_ip][dst_network] = {}
                        if dst_port not in packet_data[src_ip][dst_network]:
                            packet_data[src_ip][dst_network][dst_port] = {}
                        if dst_ip not in packet_data[src_ip][dst_network][dst_port]:
                            packet_data[src_ip][dst_network][dst_port][dst_ip] = [timestamp]  # Initialize with the first timestamp
                        else:
                            packet_data[src_ip][dst_network][dst_port][dst_ip].append(timestamp)

                except Exception as e:
                    continue

        scan_results = []  # Reset scan results for each pcap file
        for src_ip, networks in packet_data.items():
            for network, ports in networks.items():
                for port, dest_ips in ports.items():
                    if len(dest_ips) >= MIN_DESTINATIONS:
                        earliest_scan_timestamp = min(min(dest_ips.values()))
                        date_of_scan = datetime.fromtimestamp(earliest_scan_timestamp).strftime('%d.%m')
                        total_packets = sum(len(timestamps) for timestamps in dest_ips.values())
                        duration = max(max(dest_ips.values())) - min(min(dest_ips.values())) + 1
                        rate = total_packets / duration if duration > 0 else 0
                        if rate > RATE_THRESHOLD:
                            scan_results.append([date_of_scan, src_ip, network, port, len(dest_ips), total_packets, rate])

        # Generate unique CSV filename based on pcap file name
        base_filename = os.path.splitext(os.path.basename(pcap_file))[0]
        output_csv_path = os.path.join(output_csv_dir, f"{base_filename}_scan_results.csv")

        # Write to CSV file for each pcap file
        with open(output_csv_path, 'w', newline='') as csvfile:
            fieldnames = ['Date of Scan', 'Source IP', 'Network', 'Port', 'Distinct Destinations', 'Total Packets', 'Rate']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in scan_results:
                writer.writerow({
                    'Date of Scan': result[0],
                    'Source IP': result[1],
                    'Network': result[2],
                    'Port': result[3],
                    'Distinct Destinations': result[4],
                    'Total Packets': result[5],
                    'Rate': result[6],
                })

        generated_csv_files.append(output_csv_path)

        # Print after finishing each pcap file
        print(f"Finished analyzing {pcap_file} at: {datetime.now()}")

    # Combine all CSV files
    combined_csv_path = os.path.join(output_csv_dir, "combined_scan_results.csv")
    with open(combined_csv_path, 'w', newline='') as combined_csv_file:
        writer = csv.writer(combined_csv_file)
        writer.writerow(['Date of Scan', 'Source IP', 'Network', 'Port', 'Distinct Destinations', 'Total Packets', 'Rate'])  # Write header 

        for csv_file in generated_csv_files:
            with open(csv_file, 'r') as infile:
                reader = csv.reader(infile)
                next(reader)  # Skip the header row
                for row in reader:
                    writer.writerow(row)

    end_time = datetime.now()
    print(f"Script ended at: {end_time}")
    print(f"Total execution time: {end_time - start_time}")

detect_network_scan([
#add path to pcap files
], r"C:\Users\test\trest\BACHELOR\sample_foler") #Add output folder

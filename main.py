import dpkt
import socket
from collections import Counter
import csv
import os
from datetime import datetime
import requests
import pandas as pd
import geopandas as gpd
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
import sys
import glob

API_URL = "https://api.greynoise.io/v2/noise/multi/context"

# shapefile https://www.naturalearthdata.com/downloads/10m-cultural-vectors/
shapefile_path = r'C:\Users\ruskj\Downloads\ne_10m_admin_0_countries\ne_10m_admin_0_countries.shp'  # Update with your actual path

#-----------------------------LOOK FOR SCAN IN PCAP-------------------------

def detect_network_scan(pcap_files, output_csv_dir, scan_length):
    MIN_DESTINATIONS = 40
    RATE_THRESHOLD = 0
    MIN_DURATION = 60 * scan_length #minutes
    MAX_RATE_THRESHOLD = 1

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
                        latest_scan_timestamp = max(max(dest_ips.values()))
                        date_of_scan = datetime.fromtimestamp(earliest_scan_timestamp).strftime('%d.%m')
                        total_packets = sum(len(timestamps) for timestamps in dest_ips.values())
                        duration = latest_scan_timestamp - earliest_scan_timestamp + 1
                        rate = total_packets / duration if duration > 0 else 0

                        # Now also check for scan duration to identify long scans
                        if RATE_THRESHOLD < rate < MAX_RATE_THRESHOLD and duration >= MIN_DURATION:
                            scan_results.append([date_of_scan, src_ip, network, port, len(dest_ips), total_packets, rate, duration])

        # Generate unique CSV filename based on pcap file name
        base_filename = os.path.splitext(os.path.basename(pcap_file))[0]
        output_csv_path = os.path.join(output_csv_dir, f"{base_filename}_longer_scan_results.csv")

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
    combined_csv_path = os.path.join(output_csv_dir, "combined_longer_scan_results.csv")
    with open(combined_csv_path, 'w', newline='') as combined_csv_file:
        writer = csv.writer(combined_csv_file)
        writer.writerow(['Date of Scan', 'Source IP', 'Network', 'Port', 'Distinct Destinations', 'Total Packets', 'Rate'])  

        for csv_file in generated_csv_files:
            with open(csv_file, 'r') as infile:
                reader = csv.reader(infile)
                next(reader) 
                for row in reader:
                    writer.writerow(row)

    end_time = datetime.now()
    print(f"Script ended at: {end_time}")
    print(f"Total execution time: {end_time - start_time}")


#-----------------------------QUERY GREYNOISE-------------------------

def read_source_ips(csv_file_path):
    source_ips = set()
    with open(csv_file_path, mode='r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            source_ips.add(row["Source IP"])
    return source_ips

# Function to split the IP list into chunks
def chunked_ip_list(ip_set, chunk_size=1000):
    """Yield successive chunks from ip_set."""
    for i in range(0, len(ip_set), chunk_size):
        yield list(ip_set)[i:i + chunk_size]

# Function to query GreyNoise for a list of IPs and return the results
def query_greynoise(ips,API_KEY):
    all_data = [] 
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "key": API_KEY
    }

    for ip_chunk in chunked_ip_list(ips):
        payload = {"ips": ip_chunk}
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            all_data.extend(response.json()['data'])
        else:
            raise Exception(f"Failed to query GreyNoise for a chunk: {response.status_code} - {response.text}")
    
    return all_data

# Function to write the results to a CSV file
def write_results_to_csv(data, csv_output_path):
    with open(csv_output_path, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Source IP", "Country" ,"Classification", "Last Seen", "Tags"])  # Headers for output CSV
        for item in data:
            # Assign default values if none exist or if they are empty
            metadata = item.get('metadata', {})
            country = metadata.get('country', 'Not Specified')
            ip = item.get('ip', 'Unknown IP')
            classification = item.get('classification', 'Not seen') if item.get('classification') else 'Not seen'
            last_seen = item.get('last_seen', 'Not available') if item.get('last_seen') else 'Not available'
            # Ensure tags are properly formatted
            tags = item.get('tags', [])
            if not isinstance(tags, list):
                tags = []  # Set to an empty list if it's not a list
            writer.writerow([ip, country, classification, last_seen, ', '.join(tags)])


def read_and_analyze_csv(greynoise_csv_input_path):
    classifications = Counter()
    tags = Counter()
    total_entries = 0

    with open(greynoise_csv_input_path, mode='r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            total_entries += 1
            classifications[row['Classification']] += 1
            if row['Tags']:  
                for tag in row['Tags'].split(', '):
                    tags[tag] += 1

    # Print classification percentages
    print("Classification Percentages:")
    for classification, count in classifications.items():
        print(f"{classification}: {count / total_entries * 100:.2f}%")

    # Print most common tags percentages
    print("\nMost Common Tags Percentages (Top 10):")
    for tag, count in tags.most_common(10):  
        print(f"{tag}: {count / total_entries * 100:.2f}%")

#-----------------------------GREYNOISE WRITE BENIGN MALICIOUS CSV-------------------------
def write_malicious_classification_rows(csv_file, output_csv):
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        headers = reader.fieldnames
        with open(output_csv, 'w', newline='') as output_file:
            writer = csv.DictWriter(output_file, fieldnames=headers)
            writer.writeheader()
            for row in reader:
                if row['Classification'].lower() == 'malicious':
                    writer.writerow(row)
def write_benign_classification_rows(csv_file, output_csv):
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        headers = reader.fieldnames
        with open(output_csv, 'w', newline='') as output_file:
            writer = csv.DictWriter(output_file, fieldnames=headers)
            writer.writeheader()
            for row in reader:
                if row['Classification'].lower() == 'benign':
                    writer.writerow(row)
#-----------------------------GREYNOISE GET COUNTRIES AMOUNT-------------------------
def count_countries_and_write_to_csv(csv_input_path, csv_output_path):
    country_counts = Counter()  

    # Read the input CSV and count the countries
    with open(csv_input_path, mode='r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            country = row['Country'] 
            country_counts[country] += 1 

    # Write the counts to the output CSV
    with open(csv_output_path, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Country", "Count"])  # Write the header
        for country, count in country_counts.items():
            writer.writerow([country, count])
#-----------------------------GEOGRAPHICAL HEATMAP-------------------------
def plot_geographical_heatmaps(csv_output_benign_countries_path, csv_output_malicious_countries_path, shapefile_path, output_folder):
    data_df_benign = pd.read_csv(csv_output_benign_countries_path)
    data_df_malicious = pd.read_csv(csv_output_malicious_countries_path)

    world = gpd.read_file(shapefile_path)

    world_benign = world.merge(data_df_benign, how="left", left_on="ADMIN", right_on="Country")
    world_malicious = world.merge(data_df_malicious, how="left", left_on="ADMIN", right_on="Country")

    MAX_VALUE = 250

    # Plot benign data
    fig1, ax1 = plt.subplots(1, 1, figsize=(18, 10))
    world_benign.plot(column='Count', ax=ax1, legend=True, cmap='gnuplot',
                      norm=Normalize(vmin=0, vmax=MAX_VALUE),
                      legend_kwds={'orientation': "horizontal", 'shrink': 0.5, 'aspect': 20, 'pad': 0.05},
                      missing_kwds={'color': 'lightgrey'}, edgecolor='black', linewidth=0.1)
    plt.subplots_adjust(left=0.045, bottom=0.0, right=0.964, top=1, wspace=0.2, hspace=0.2)
    benign_output_path = f'{output_folder}\\24_hours_scans_benign.png'
    plt.savefig(benign_output_path, dpi=300, format='png')
    plt.close(fig1)

    # Plot malicious data
    fig2, ax2 = plt.subplots(1, 1, figsize=(18, 10))
    world_malicious.plot(column='Count', ax=ax2, legend=True, cmap='gnuplot',
                         norm=Normalize(vmin=0, vmax=MAX_VALUE),
                         legend_kwds={'orientation': "horizontal", 'shrink': 0.5, 'aspect': 20, 'pad': 0.05},
                         missing_kwds={'color': 'lightgrey'}, edgecolor='black', linewidth=0.1)
    plt.subplots_adjust(left=0.045, bottom=0.0, right=0.964, top=1, wspace=0.2, hspace=0.2)
    malicious_output_path = f'{output_folder}\\24_hours_scans_malicious.png'
    plt.savefig(malicious_output_path, dpi=300, format='png')
    plt.close(fig2)

def detect_network_scan_wrapper(pcapfiles, output_folder, scan_length):
    detect_network_scan(pcapfiles, output_folder, scan_length)

def greynoise_operations_wrapper(API_KEY):
    # Read the source IPs from the provided CSV
    source_ips = read_source_ips(greynoise_csv_input_path)
    print(f"Read {len(source_ips)} unique source IPs.")
    
    # Query GreyNoise for the list of source IPs
    print("Querying GreyNoise for IP information...")
    greynoise_data = query_greynoise(source_ips,API_KEY)
    
    # Write the results to a new CSV file
    write_results_to_csv(greynoise_data, GREYNOISE_CSV_OUTPUT_PATH)
    print(f"Results written to {GREYNOISE_CSV_OUTPUT_PATH}")
    
def classification_and_country_count_operations_wrapper():
    write_malicious_classification_rows(GREYNOISE_CSV_OUTPUT_PATH, output_malicious_csv_file)
    write_benign_classification_rows(GREYNOISE_CSV_OUTPUT_PATH, output_benign_csv_file)
    count_countries_and_write_to_csv(csv_input_benign_path, csv_output_benign_countries_path)
    count_countries_and_write_to_csv(csv_input_malicious_path, csv_output_malicious_countries_path)

def plot_geographical_heatmaps_wrapper():
    plot_geographical_heatmaps(csv_output_benign_countries_path, csv_output_malicious_countries_path, shapefile_path, output_folder)

if __name__ == '__main__':

    print("Bachelor Ruben Skjelstad scan detection, greynoise query and graphical heatmap generation!")
    output_folder = input("Enter the output folder path: ")

    pcap_file_input  = input("Enter the folder where the pcap file is located, the program will take all the pcap file in the folder and analyse them!\n")
    pattern = os.path.join(pcap_file_input , '*.cap')
    pcapfiles = glob.glob(pattern)
    if pcapfiles: 
        print(f"Found {len(pcapfiles)} pcap files.")
        for file in pcapfiles:
            print(file)
    else:
        print("No pcap files found in the specified directory.")
    scan_length = input("Enter the length in MINUTES for the length of the network scan: ")
    try:
        scan_length_minutes = int(scan_length)
    except ValueError:
        print("Invalid scan length. Please enter a numeric value.")
        sys.exit(1)
    # Determine the naming convention based on the scan length
    if scan_length_minutes < 60:
        time_label = f'{scan_length_minutes}_minutes'
    else:
        hours = scan_length_minutes // 60
        time_label = f'{hours}_hours'

    detect_network_scan_wrapper(pcapfiles, output_folder, scan_length)
    
    greynoise_csv_input_path = os.path.join(output_folder, 'combined_longer_scan_results.csv')
    GREYNOISE_CSV_OUTPUT_PATH = os.path.join(output_folder, f'{time_label}_scans_greynoise.csv')
    output_malicious_csv_file = os.path.join(output_folder, f'{time_label}_scans_malicious.csv')
    output_benign_csv_file = os.path.join(output_folder, f'{time_label}_scans_benign.csv')
    csv_input_malicious_path = output_malicious_csv_file
    csv_output_malicious_countries_path = os.path.join(output_folder, f'{time_label}_scans_malicious_countries.csv')
    csv_input_benign_path = output_benign_csv_file
    csv_output_benign_countries_path = os.path.join(output_folder, f'{time_label}_scans_benign_countries.csv')
    
    API_KEY = input("What is your Greynoise API key?\n")
    greynoise_operations_wrapper(API_KEY)
    classification_and_country_count_operations_wrapper()
    plot_geographical_heatmaps_wrapper()

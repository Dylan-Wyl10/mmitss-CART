import socket
import json
import time
import os

# Load configuration file
config_file_path = "/nojournal/bin/mmitss-phase3-master-config.json"
with open(config_file_path, 'r') as configFile:
    config = json.load(configFile)

# Get host IP and port from config
host_ip = config["HostIp"]
port = config["PortNumber"]["PrioritySolver"]  # Use PrioritySolver port

folder_path = "test_cases"  # Folder containing JSON test files

# Get a list of all JSON files in the folder, sorted alphabetically
file_paths = sorted([os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(".json")])

# Create UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

if not file_paths:
    print(f"No JSON files found in folder: {folder_path}")
else:
    for i, file_path in enumerate(file_paths):
        try:
            with open(file_path, "r") as f:
                data = f.read()

            # Send file data to NewSolver
            s.sendto(data.encode(), (host_ip, port))
            print(f"Sent {file_path} at {time.time()} to {host_ip}:{port}")

            # Wait for 10 seconds before sending the next file
            if i < len(file_paths) - 1:
                print(f"Waiting 10 seconds before sending the next file...")
                time.sleep(10)

        except FileNotFoundError:
            print(f"Error: File {file_path} not found. Skipping...")

# Close socket after sending all files
s.close()

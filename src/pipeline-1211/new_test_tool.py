import socket
import json
import time

config_path = "/nojournal/bin/mmitss-phase3-master-config.json"
with open(config_path, 'r') as config_file:
    config = json.load(config_file)

host_ip = config["HostIp"]
port = config["PortNumber"]["PrioritySolver"]

with open("lansing_testing/intervals.json", "r") as f:
    interval_data = json.load(f)

files = interval_data["files"]
intervals = interval_data["intervals"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i, file_path in enumerate(files):
    with open(file_path, "r") as f:
        data = f.read()

    sock.sendto(data.encode(), (host_ip, port))
    print(f"Sent {file_path} at {time.strftime('%Y-%m-%d %H:%M:%S')} to {host_ip}:{port}")

    if i < len(files) - 1:
        wait_time = intervals[i + 1]
        print(f"Waiting {wait_time:.2f} seconds...")
        time.sleep(wait_time)

sock.close()

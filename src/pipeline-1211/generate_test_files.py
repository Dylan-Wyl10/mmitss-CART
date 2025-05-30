import json
import os
from datetime import datetime

input_json_path = "raw_received_messages1.json"
output_folder = "lansing_testing"
os.makedirs(output_folder, exist_ok=True)

with open(input_json_path, 'r') as f:
    raw_messages = json.load(f)

timestamps = []
file_list = []

for i, msg in enumerate(raw_messages):
    ts = datetime.strptime(msg["Timestamp"], "%Y-%m-%d %H:%M:%S %Z")
    timestamps.append(ts)
    data = json.loads(msg["RawData"])
    filename = f"{i:02d}.json"
    filepath = os.path.join(output_folder, filename)
    file_list.append(filepath)
    with open(filepath, 'w') as f_out:
        json.dump(data, f_out, indent=4)

intervals = [0]
for i in range(1, len(timestamps)):
    delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
    intervals.append(delta)

interval_data = {
    "files": file_list,
    "intervals": intervals
}
with open(os.path.join(output_folder, "intervals.json"), "w") as f:
    json.dump(interval_data, f, indent=4)

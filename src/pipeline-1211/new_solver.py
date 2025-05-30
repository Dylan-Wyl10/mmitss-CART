#!/usr/bin/env python3
# Version: v10-fix
import json
import time
import subprocess
from pathlib import Path
import socket 
import datetime

msg_type_map = {
    "PriorityRequest": "SnmpSetRequest"
}

oid_map = {
    "PriorityRequest": "1.3.6.1.4.1.1206.4.2.11.2.1.1"
}

###############################################################################
# Status Table: mapping integer statuses to descriptive strings               #
###############################################################################

REQUEST_STATUS_CODES = {
    1:  "idleNotValid",
    2:  "readyQueued",
    3:  "readyOverridden",
    4:  "activeProcessing",
    5:  "activeCancel",
    6:  "activeOverride",
    7:  "activeNotOverridden",
    8:  "closedCanceled",
    9:  "reserviceError",
    10: "closedTimeToLiveError",
    11: "closedTimerError",
    12: "closedStrategyError",
    13: "closedCompleted",
    14: "activeAdjustNotNeeded",
    15: "closedFlash"
}

class NewSolver:
    def __init__(self, host_ip, port, output_dir, snmp_target, snmp_community):
        self.host_ip = host_ip
        self.port = port
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.snmp_target = snmp_target
        self.snmp_community = snmp_community

        self.poll_interval = 0.5
        self.active_requests = []
        self.removal_queue = {}

        # Set up UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host_ip, self.port))
        print(f"NewSolver listening on {self.host_ip}:{self.port}")
        
        # Clear previous SNMP log at startup
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.snmp_log_path = self.output_dir / f"snmp_log_{timestamp}.json"
        self.snmp_log_path.write_text("[]")

        self.monitoring_log_path = self.output_dir / f"monitoring_log_{timestamp}.json"
        self.monitoring_log_path.write_text("[]")
        
        self.received_log_path = self.output_dir / f"received_requests_log_{timestamp}.json"
        self.received_log_path.write_text("[]") 
        
        self.log_signal_plan()
        
    def run(self):
        """Continuously listens for new priority request files and processes them inside monitor_requests()."""
        print("\n=== NewSolver is starting ===")
        self.monitor_requests()  


    ###########################################################################
    # PART 1: READING INPUT & GENERATING SNMP REQUESTS
    ###########################################################################
    def snmp_get_value(self, oid):
        try:
            result = subprocess.run([
                "snmpget", "-v1", "-c", self.snmp_community, self.snmp_target, oid
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            response = result.stdout.strip()
            if "INTEGER:" in response:
                return int(response.split("INTEGER:")[1].strip())
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] SNMP GET failed for OID {oid}: {e.stderr}")
        return None

    def log_signal_plan(self):
        log_path = self.snmp_log_path
        if log_path.exists():
            try:
                log_data = json.loads(log_path.read_text())
            except json.JSONDecodeError:
                log_data = []
        else:
            log_data = []

        plan_oid = "1.3.6.1.4.1.1206.4.2.1.5.4.0"
        plan_number = self.snmp_get_value(plan_oid)

        if plan_number is None:
            print("[ERROR] Failed to get current event plan number.")
            return

        print(f"\n[INFO] Current Event Plan: {plan_number}")
        signal_plan = {"EventPlan": plan_number, "Phases": []}

        for phase in range(1, 17):
            green_oid = f"1.3.6.1.4.1.1206.4.2.1.4.9.1.3.{plan_number}.{phase}"
            yellow_oid = f"1.3.6.1.4.1.1206.4.2.1.1.2.1.8.{phase}"
            red_oid = f"1.3.6.1.4.1.1206.4.2.1.1.2.1.9.{phase}"
            reduction_oid = f"1.3.6.1.4.1.1206.4.2.11.3.6.1.1.{plan_number}.{phase}"
            extension_oid = f"1.3.6.1.4.1.1206.4.2.11.3.6.1.2.{plan_number}.{phase}"

            green = self.snmp_get_value(green_oid)
            yellow = self.snmp_get_value(yellow_oid)
            red = self.snmp_get_value(red_oid)
            reduction = self.snmp_get_value(reduction_oid)
            extension = self.snmp_get_value(extension_oid)

            phase_info = {
                "Phase": phase,
                "Green": green,
                "Yellow": yellow / 10 if yellow is not None else None,
                "Red": red / 10 if red is not None else None,
                "MaxReduction": reduction,
                "MaxExtension": extension
            }
            signal_plan["Phases"].append(phase_info)

            print(f"Phase {phase:2d}: Green={green}, Yellow={phase_info['Yellow']}, Red={phase_info['Red']}, "
                  f"MaxReduction={reduction}, MaxExtension={extension}")

        log_data.insert(0, {"InitialSignalPlan": signal_plan})
        log_path.write_text(json.dumps(log_data, indent=4))
    
    
    def vehicle_id_to_hex(self, vehicle_id_str: str) -> str:
        """
        Convert a vehicle ID string into a 34-digit hex:
        each char => ASCII hex, zero-padded/truncated to length 34.
        """
        hex_representation = ''.join(f"{ord(c):02x}" for c in vehicle_id_str)
        return hex_representation.ljust(34, '0')[:34]
    
    def find_next_available_id(self):
        """Finds the first available priority request ID (1-255) that is not currently active."""
        used_ids = {int(req["requestIDHex"], 16) for req in self.active_requests}
        
        for i in range(1, 256):  # Priority Request IDs range from 1 to 255
            if i not in used_ids:
                return f"{i:02x}"  # Return as hex string (e.g., "01", "02", ...)
        
        raise ValueError("No available Priority Request IDs!")

    def generate_snmp_requests(self, data: dict):
        """
        1) Process the input data
        2) Generate snmp_request_XX.json files
        3) Populate self.active_requests with data for sets + gets (status)
        """
        msg_type = data.get("MsgType")
        output_msg_type = msg_type_map.get(msg_type, "Unknown")
        set_oid = oid_map.get(msg_type, "Unknown")
        new_oid = "1.3.6.1.4.1.1206.4.2.11.2.1.1" # OID for new requests
        update_oid = "1.3.6.1.4.1.1206.4.2.11.2.2.1"  # OID for update
        clear_oid = "1.3.6.1.4.1.1206.4.2.11.2.5.1"  # OID for clearing requests
        console_logs = []

        if msg_type == "ClearRequest":
            msg = "[INFO] Received ClearRequest: Clearing all active requests."
            console_logs.append(msg)
            print("\n",msg)

            for req in self.active_requests:
                #if req["requestIDHex"] not in self.removal_queue:  # Only clear active requests
                    req["setOID"] = clear_oid  
                    req["status"] = "pending"  # Mark as pending for sending
                    req["setValue"] = (
                        req["requestIDHex"] + self.vehicle_id_to_hex(req["vehicleIDStr"]) +
                        req["classType"] + req["classLevel"] + req["priorityRequestPhase"]
                    )

                    msg = f"[CLEAR] RequestID={req['requestIDHex']} for VehicleID={req['vehicleIDStr']} marked for clearing."
                    console_logs.append(msg)
                    print(msg)
                    self.removal_queue[req["requestIDHex"]] = time.time() + 60

            self.append_to_monitoring_log(console_logs)
            return 

        priority_list = data.get("PriorityRequestList", {})
        requestor_info = priority_list.get("requestorInfo", [])
        
        # Count existing (classType, priorityRequestPhase) in active requests (excluding removal queue)
        current_counts = {}
        for req in self.active_requests:
            if req["requestIDHex"] not in self.removal_queue:  # Exclude removal queue
                key = (req["classType"], req["priorityRequestPhase"])
                current_counts[key] = current_counts.get(key, 0) + 1

        for request in requestor_info:
            # Priority Request ID (hex string)
            priority_request_id = self.find_next_available_id()  # Get first available ID

            # Convert vehicle ID
            vehicle_id_str = str(request["vehicleID"])
            vehicle_id_hex = self.vehicle_id_to_hex(vehicle_id_str)

            requested_signal_group = request.get("requestedSignalGroup", 0)
            priority_request_phase = f"{requested_signal_group:02x}"
            
            vehicle_type = request.get("vehicleType", 0)
            # Use fixed class type for now
            class_type = "07"
            
            # Check if the vehicle ID already exists in an active request
            matching_request = None
            for req in self.active_requests:
                if req["requestIDHex"] not in self.removal_queue and req["vehicleIDStr"] == vehicle_id_str:
                    if req["classType"] == class_type and req["priorityRequestPhase"] == priority_request_phase:
                        print(f"[Update Matching] for VehicleID={vehicle_id_str}, ClassType={class_type}, Phase={priority_request_phase}, "
                            f"Matches with ID={req['requestIDHex']}, VehicleID={req['vehicleIDStr']}, ClassType={req['classType']}, Phase={req['priorityRequestPhase']}")
                        matching_request = req  # Found a matching active request
                    else:
                        print(f"[ERROR] Conflicting request for VehicleID={vehicle_id_str}: "
                            f"Existing request has ClassType={req['classType']}, Phase={req['priorityRequestPhase']}, "
                            f"but new request has ClassType={class_type}, Phase={priority_request_phase}")
                        continue  
                        ETA = int(request.get("ETA", 0))
                        
            ETA = int(request.get("ETA", 0))
            ETD = int(ETA + request.get("ETA_Duration", 0))
            ETA_hex = f"{ETA:04x}"
            ETD = ETD
            ETD_hex = f"{ETD:04x}"
            
            if matching_request:
                # Use the same request ID and send an update instead of a new set command
                priority_request_id = matching_request["requestIDHex"]
                set_oid = update_oid  # Change OID to update process
                class_level = matching_request["classLevel"]  # Keep the previous class level

                # Update the existing request's values
                matching_request["setOID"] = set_oid  # Change to update OID
                matching_request["setValue"] = (
                    priority_request_id + self.vehicle_id_to_hex(vehicle_id_str) +
                    class_type + class_level + priority_request_phase + ETA_hex + ETD_hex
                )
                matching_request["currentETA"] = ETA
                matching_request["currentETD"] = ETD
                matching_request["status"] = "pending"
                msg = f"[INFO] Updating existing request with ID={priority_request_id} for VehicleID={vehicle_id_str}"
                console_logs.append(msg)
                print(msg)

            else:
                set_oid = new_oid
                # Assign a new request ID
                priority_request_id = self.find_next_available_id()

                # Dynamically count existing requests and assign class level
                key = (class_type, priority_request_phase)
                current_counts[key] = current_counts.get(key, 0) + 1
                class_level = f"{current_counts[key]:02x}"  # Convert to hex

                # Store data for monitoring
                request_id_dec = int(priority_request_id, 16)  # hex -> decimal

                # OIDs for status poll
                status_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.9.{request_id_dec}"

                # Build the SNMP set value
                snmp_value = (
                    priority_request_id
                    + vehicle_id_hex
                    + class_type
                    + class_level
                    + priority_request_phase
                    + ETA_hex
                    + ETD_hex
                )

                self.active_requests.append({
                "requestIDHex": priority_request_id,  
                "requestIDDec": request_id_dec, 
                "vehicleIDStr": vehicle_id_str, 
                "setOID": set_oid,
                "setValue": snmp_value,
                "statusOID": status_oid,
                "status": "pending",
                "currentETA": ETA,
                "currentETD": ETD,
                "classType": class_type,     
                "classLevel": class_level,   
                "priorityRequestPhase": priority_request_phase  
                })

    ###########################################################################
    # PART 2: SENDING THE SNMP SET COMMANDS
    ###########################################################################

    def send_all_snmp_sets(self):
        """Loop over each request and perform an SNMP Set."""
        log_path = self.snmp_log_path

        # Load existing log
        if log_path.exists():
            with log_path.open("r", encoding="utf-8") as f:
                try:
                    log_data = json.load(f)
                except json.JSONDecodeError:
                    log_data = []
        else:
            log_data = []
            
        for req in self.active_requests:
            if req["status"] in ("pending"):
                command = [
                    "snmpset",
                    "-v1",
                    "-c", self.snmp_community,
                    self.snmp_target,
                    req["setOID"],
                    "x",  # indicate hex type
                    req["setValue"]
                ]
                success = self.snmp_set_hex(req["setOID"], req["setValue"])
                timestamp_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                
                # Determine action type
                if req["setOID"].endswith("2.5.1"):
                    action_type = "Clear Request"
                elif req["setOID"].endswith("2.2.1"):
                    action_type = "Update Request"
                else:
                    action_type = "New Request"
                
                # Log request detaicls
                log_entry = {
                    "Timestamp": timestamp_utc,
                    "Command": " ".join(command),
                    "RequestID": req["requestIDHex"],
                    "VehicleID": req["vehicleIDStr"],
                    "ClassType": req["classType"],
                    "ClassLevel": req["classLevel"],
                    "PriorityRequestPhase": req["priorityRequestPhase"],
                    "ETA": req["currentETA"],
                    "ETD": req["currentETD"],
                    "Status": req["status"],
                    "Action": action_type,
                    "Success": success
                }
                
                log_data.append(log_entry)
                
                if success:
                    print(
                        f"[{action_type}] SNMP SET sent for RequestID={req['requestIDHex']}, "
                        f"VehicleID={req['vehicleIDStr']}, "
                        f"VehicleClassType={req['classType']}, "
                        f"VehicleClassLevel={req['classLevel']}, "
                        f"PriorityRequestPhase={req['priorityRequestPhase']}, "
                        f"ETA={req['currentETA']}, "
                        f"ETD={req['currentETD']}"
                    )
                    req["status"] = "active"
                else:
                    print(f"SNMP SET failed for RequestID={req['requestIDHex']}")
                    req["status"] = "failed"
        # Save updated log
        with log_path.open("w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=4)

    def snmp_set_hex(self, oid: str, hex_value: str) -> bool:
        """
        Execute an SNMP SET with a hex string. Return True on success, False otherwise.
        """
        command = [
            "snmpset",
            "-v1",
            "-c", self.snmp_community,
            self.snmp_target,
            oid,
            "x",  # indicate hex type
            hex_value
        ]
        try:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print("SNMP SET Error:\n", e.stderr)
            return False

    ###########################################################################
    # PART 3: MONITORING LOOP
    ###########################################################################
    def monitor_requests(self):
        """
        Continuously:
        - Checks for new priority request files every second
        - Processes new requests immediately
        - Monitors all active requests (old and new) together
        """
        print("=== NewSolver is now actively listening for requests and monitoring ===")

        self.removal_queue = {}  # Store completed requests to be removed after 60s

        while True:
            console_logs = []
            # === Check for new input every second ===
            self.socket.settimeout(self.poll_interval)  # Set 1-second timeout to avoid blocking
            try:
                data, addr = self.socket.recvfrom(65535) 
                received_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

                # Load existing log
                if self.received_log_path.exists():
                    with self.received_log_path.open("r", encoding="utf-8") as f:
                        try:
                            log_data = json.load(f)
                        except json.JSONDecodeError:
                            log_data = []
                else:
                    log_data = []

                # Append new entry
                log_entry = {
                    "Timestamp": received_time,
                    "Source": addr,  # Store sender IP and port
                    "RawData": data.decode(errors="ignore")
                }
                log_data.append(log_entry)

                # Save log
                with self.received_log_path.open("w", encoding="utf-8") as f:
                    json.dump(log_data, f, indent=4)

                input_data = json.loads(data.decode())

                msg = "=== Received New Priority Request ==="
                console_logs.append(msg)
                print("\n",msg)

                self.generate_snmp_requests(input_data)  # Process new request
                self.send_all_snmp_sets()

            except socket.timeout:
                pass  # No new input, continue monitoring existing requests

            # === Monitor all active requests ===   
            msg = "=== Monitoring Active Requests ==="
            console_logs.append(msg)
            print("\n",msg)
            
            # Print the epoch time before showing the requests
            epoch_time = int(time.time())
            console_logs.append(f"Epoch Time: {epoch_time}")
            print(f"Epoch Time: {epoch_time}")

            incomplete = [r for r in self.active_requests if r["status"] not in (
                "closedCompleted", "idleNotValid", "closedCanceled", "closedTimeToLiveError",
                "closedTimerError", "closedStrategyError", "closedFlash", "reserviceError"
            )]

            if not incomplete and not self.removal_queue:
                msg = "All requests have reached terminal states. Monitoring continues..."
                console_logs.append(msg)
                print(msg)
                
            # Poll each incomplete request
            for req in incomplete:
                status_response = self.snmp_get(req["statusOID"])
                status_code = self.extract_status_code(status_response) if status_response else None

                if status_code is not None:
                    status_name = REQUEST_STATUS_CODES.get(status_code, f"Unknown({status_code})")
                    req["status"] = status_name

                    if status_code in (1, 8, 9, 10, 11, 12, 13, 15):  # Terminal states
                        msg = f"Request {req['requestIDHex']} => {status_name}. Marking for removal in 60s."
                        console_logs.append(msg)
                        print(msg)
                        self.removal_queue[req["requestIDHex"]] = time.time() + 60

            # Remove completed requests after 60 seconds
            current_time = time.time()
            for request_id_hex in list(self.removal_queue.keys()):
                if current_time >= self.removal_queue[request_id_hex]:
                    self.active_requests = [r for r in self.active_requests if r["requestIDHex"] != request_id_hex]
                    msg = f"Request {request_id_hex} fully removed. ID now available."
                    console_logs.append(msg)
                    print(msg)
                    del self.removal_queue[request_id_hex]

            # Print and log active requests
            self.print_incomplete_requests()
            self.append_to_monitoring_log(console_logs)

    def append_to_monitoring_log(self, console_logs):
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        epoch_time = int(time.time())
        monitor_snapshot = {
            "EpochTime": epoch_time,
            "Timestamp": timestamp,
            "ConsoleOutput": console_logs
        }

        if self.monitoring_log_path.exists():
            with self.monitoring_log_path.open("r", encoding="utf-8") as f:
                try:
                    monitor_log = json.load(f)
                except json.JSONDecodeError:
                    monitor_log = []
        else:
            monitor_log = []

        monitor_log.append(monitor_snapshot)
        with self.monitoring_log_path.open("w", encoding="utf-8") as f:
            json.dump(monitor_log, f, indent=4)
    
    def snmp_get(self, oid: str) -> str:
        """Execute snmpget and return the stdout. Return None on error."""
        command = [
            "snmpget",
            "-v1",
            "-c", self.snmp_community,
            self.snmp_target,
            oid
        ]

        try:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print("SNMP GET Error:\n", e.stderr)
            return None

    def extract_status_code(self, snmp_response: str):
        """
        Parse the net-snmp response to extract the integer after 'INTEGER:'.
        Example:
          SNMPv2-SMI::iso.3.6.1.xxxx = INTEGER: 4
          => 4
        Returns None if we can't parse an integer.
        """
        marker = "INTEGER:"
        idx = snmp_response.find(marker)
        if idx == -1:
            return None

        after = snmp_response[idx + len(marker):].strip()
        parts = after.split()
        if not parts:
            return None

        try:
            return int(parts[0])
        except ValueError:
            return None

    def print_incomplete_requests(self):
        """Print out the status of all incomplete requests each time step."""
        # The incomplete requests are those still not in terminal states
        incomplete = [r for r in self.active_requests
                       if r["status"] not in ("closedCompleted", "idleNotValid", "closedCanceled",
                                              "closedTimeToLiveError", "closedTimerError",
                                              "closedStrategyError", "closedFlash",
                                              "reserviceError")]
        console_logs = []
        
        # Print active requests
        if not incomplete:
            msg = "No incomplete requests at this moment."
            console_logs.append(msg)
            print(msg)
        else:
            console_logs.append("--- Incomplete Requests ---")
            print("\n--- Incomplete Requests ---")
            for req in incomplete:
                line = (
                    f"RequestID={req['requestIDHex']}, "
                    f"VehicleID={req['vehicleIDStr']}, "
                    f"VehicleClassType={req['classType']}, "
                    f"VehicleClassLevel={req['classLevel']}, "
                    f"PriorityRequestPhase={req['priorityRequestPhase']}, "
                    f"Status={req['status']}"
                )
                console_logs.append(line)
                print(line)
            console_logs.append("---------------------------")
            print("---------------------------\n")

        # Log snapshot
        self.append_to_monitoring_log(console_logs)

if __name__ == "__main__":
    # Load configuration file
    config_file_path = "/nojournal/bin/mmitss-phase3-master-config.json"
    with open(config_file_path, 'r') as configFile:
        config = json.load(configFile)

    # Attempt to extract values
    try:
        host_ip = config["HostIp"]
        port = config["PortNumber"]["PrioritySolver"]
        controller_ip = config["SignalController"]["IpAddress"]
        ntcip_port = config["SignalController"]["NtcipPort"]
        snmp_community = config["SignalController"]["SNMPCommunity"]

        snmp_target = f"{controller_ip}:{ntcip_port}"

        app = NewSolver(
            host_ip=host_ip,
            port=port,
            output_dir="/nojournal/bin/log-1211",
            snmp_target=snmp_target,
            snmp_community=snmp_community
        )
        app.run()

    except KeyError as e:
        print(f"[ERROR] Missing key in configuration: {e}")
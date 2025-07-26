#!/usr/bin/env python3
# Version: v12
import json
import time
import subprocess
from pathlib import Path
import socket 
import datetime
import threading

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

TERMINAL_STATUS_NAMES = (
    "closedCompleted", "idleNotValid", "closedCanceled",
    "closedTimeToLiveError", "closedTimerError",
    "closedStrategyError", "closedFlash", "reserviceError"
)

class NewSolver:
    def __init__(self, host_ip, port, output_dir, snmp_target, snmp_community):
        self.host_ip = host_ip
        self.port = port
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.snmp_target = snmp_target
        self.snmp_community = snmp_community        
        
        # Clear previous SNMP log at startup
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.snmp_log_path = self.output_dir / f"snmp_log_{timestamp}.json"
        self.snmp_log_path.write_text("[]")

        self.monitoring_log_path = self.output_dir / f"monitoring_log_{timestamp}.json"
        self.monitoring_log_path.write_text("[]")
        
        self.received_log_path = self.output_dir / f"received_requests_log_{timestamp}.json"
        self.received_log_path.write_text("[]") 

        self.poll_interval = 0.5
        self.used_ids = set()  # Persistent: only grows, unless cleared as described.
        self.prev_req_ids = set()  # Set of (vehicleIDStr, classType, priorityRequestPhase)
        self.active_requests = {}  # Always overwritten by scans/updates.
        
        self.monitoring_console_logs = []
        self.monitoring_log_lock = threading.Lock()
        
        # Set up UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host_ip, self.port))
        self.log(f"NewSolver listening on {self.host_ip}:{self.port}", level="INFO", tag="INIT")
    
        self.log_signal_plan()
        self.load_active_requests_from_controller()
        
    def run(self):
        """Continuously listens for new priority request files and processes them inside monitor_requests()."""
        self.log("=== NewSolver is starting ===", tag="STARTUP")
        self.flush_monitoring_log()
        self.monitor_requests()  

    def log(self, msg, level="INFO", tag=None):
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        prefix = f"[{level}]"
        if tag:
            prefix += f"[{tag}]"
        out_msg = f"{timestamp} {prefix} {msg}"
        print(out_msg)
        self.add_to_monitoring_log(out_msg)
        self.flush_monitoring_log()

    def add_to_monitoring_log(self, msg):
        if not hasattr(self, "_monitoring_log_buffer"):
            self._monitoring_log_buffer = []
        self._monitoring_log_buffer.append(msg)

    def flush_monitoring_log(self):
        with self.monitoring_log_lock:
            if hasattr(self, "_monitoring_log_buffer") and self._monitoring_log_buffer:
                # Read old logs
                if self.monitoring_log_path.exists():
                    with self.monitoring_log_path.open("r", encoding="utf-8") as f:
                        try:
                            monitor_log = json.load(f)
                        except json.JSONDecodeError:
                            monitor_log = []
                else:
                    monitor_log = []
                # Append all new lines
                monitor_log.extend(self._monitoring_log_buffer)
                # Write back
                with self.monitoring_log_path.open("w", encoding="utf-8") as f:
                    json.dump(monitor_log, f, indent=4)
                self._monitoring_log_buffer = []


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
            else:
                self.log(f"SNMP GET for OID {oid} did not return an INTEGER. Response: {response}", level="WARNING", tag="SNMP")
        except subprocess.CalledProcessError as e:
            self.log(f"SNMP GET failed for OID {oid}: {e.stderr}", level="ERROR", tag="SNMP")
        return None
    
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
            self.log(f"SNMP GET failed for OID {oid}: {e.stderr}", level="ERROR", tag="SNMP")
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
            self.log("[ERROR] Failed to get current event plan number.", level="ERROR", tag="SignalPlan")
            return

        self.log(f"Current Event Plan: {plan_number}", tag="SignalPlan")
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

            msg = (f"Phase {phase:2d}: Green={green}, Yellow={phase_info['Yellow']}, "
                f"Red={phase_info['Red']}, MaxReduction={reduction}, MaxExtension={extension}")
            self.log(msg, tag="SignalPlan")

        log_data.insert(0, {"InitialSignalPlan": signal_plan})
        log_path.write_text(json.dumps(log_data, indent=4))
    
    def hex_string_to_ascii(self, hex_str):
        """Convert a hex string (as returned by SNMP for vehicle ID) to ASCII string."""
        bytes_object = bytes.fromhex(hex_str)
        return bytes_object.decode(errors="ignore").replace('\x00', '').strip()
    
    def scan_controller_active_requests(self, verbose=False):
        """
        Scan controller table rows 1-10.
        Return:
            - active_requests: dict {request_id: {info}}
            - active_ids: set of currently active request_ids (for diagnostic, not for used_ids logic)
        If verbose=True, print each active request.
        """
        active_requests = {}
        active_ids = set()

        for row_id in range(1, 11):
            status_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.9.{row_id}"
            status_response = self.snmp_get(status_oid)
            if not status_response:
                self.log(f"Row {row_id}: SNMP status get failed or empty.", level="WARNING", tag="ControllerScan")
                continue
            status_code = self.extract_status_code(status_response)
            status_name = REQUEST_STATUS_CODES.get(status_code, f"Unknown({status_code})")
            if status_name in TERMINAL_STATUS_NAMES:
                continue  # Not active

            # Fetch details for this row
            request_id_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.2.{row_id}"
            vehicle_id_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.3.{row_id}"
            class_type_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.4.{row_id}"
            class_level_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.5.{row_id}"
            eta_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.7.{row_id}"
            etd_oid = f"1.3.6.1.4.1.1206.4.2.11.1.1.1.8.{row_id}"

            request_id_val = self.snmp_get_value(request_id_oid)
            vehicle_id_hex = self.snmp_get(vehicle_id_oid)
            class_type_val = self.snmp_get_value(class_type_oid)
            class_level_val = self.snmp_get_value(class_level_oid)
            eta_val = self.snmp_get_value(eta_oid)
            etd_val = self.snmp_get_value(etd_oid)

            # Convert vehicle ID hex to string
            if vehicle_id_hex and "Hex-STRING:" in vehicle_id_hex:
                hex_str = vehicle_id_hex.split("Hex-STRING:")[1].strip().replace(" ", "")
                vehicle_id_str = self.hex_string_to_ascii(hex_str)
                if vehicle_id_str.startswith('.'):
                    vehicle_id_str = '-' + vehicle_id_str[1:]
            else:
                vehicle_id_str = "unknown"

            req_hex = f"{request_id_val:02x}" if request_id_val is not None else "unknown"
            class_type_hex = f"{class_type_val:02x}" if class_type_val is not None else "unknown"
            class_level_hex = f"{class_level_val:02x}" if class_level_val is not None else "unknown"

            msg = (f"[LOADED] Row={row_id}, RequestID={req_hex}, VehicleID={vehicle_id_str}, "
                f"VehicleClassType={class_type_hex}, VehicleClassLevel={class_level_hex}, "
                f"Status={status_name}, ETA={eta_val}, ETD={etd_val}")
            if verbose:
                self.log(msg, tag="ControllerScan")
            
            if request_id_val is not None:
                active_requests[request_id_val] = ({
                    "requestIDHex": req_hex,
                    "requestIDDec": request_id_val,
                    "vehicleIDStr": vehicle_id_str,
                    "setOID": None,
                    "setValue": None,
                    "statusOID": status_oid,
                    "status": status_name,
                    "currentETA": eta_val,
                    "currentETD": etd_val,
                    "classType": class_type_hex,
                    "classLevel": class_level_hex,
                    "priorityRequestPhase": "unknown"  # No phase info
                })
                active_ids.add(request_id_val)
            else:
                self.log(f"Row {row_id}: request_id_val is None, skipping.", level="WARNING", tag="ControllerScan")
        return active_requests, active_ids
    
    def load_active_requests_from_controller(self):
        """
        Populate self.active_requests and update self.used_ids as needed.
        Print all loaded requests.
        """
        self.log("Loading existing active requests from controller...", tag="INIT")
        loaded_requests, _ = self.scan_controller_active_requests(verbose=True)
        self.active_requests = loaded_requests
        # Add all loaded request IDs into self.used_ids (do not remove any IDs)
        for req_id in loaded_requests:
            self.used_ids.add(req_id)
        self.log(f"{len(self.active_requests)} active requests loaded from controller.", tag="INIT")


    def vehicle_id_to_hex(self, vehicle_id_str: str) -> str:
        """
        Convert a vehicle ID string into a 34-digit hex:
        each char => ASCII hex, zero-padded/truncated to length 34.
        """
        hex_representation = ''.join(f"{ord(c):02x}" for c in vehicle_id_str)
        return hex_representation.ljust(34, '0')[:34]
    
    def find_next_available_id(self):
        """
        Find the smallest unused ID in 1-255.
        If all are used, clear used_ids and start from scratch.
        Returns hex string.
        """
        for i in range(1, 256):
            if i not in self.used_ids:
                return f"{i:02x}"
        # All used, reset and start fresh
        self.log("All possible IDs have been used. Clearing used_ids for recycling.", tag="REQUEST")
        self.used_ids.clear()
        return "01"

    def generate_snmp_requests(self, data: dict):
        """
        1) Process the input data
        2) Generate snmp_request_XX.json files
        3) Populate self.active_requests with data for sets + gets (status)
        """
        msg_type = data.get("MsgType")
        new_oid = "1.3.6.1.4.1.1206.4.2.11.2.1.1" # OID for new requests
        update_oid = "1.3.6.1.4.1.1206.4.2.11.2.2.1"  # OID for update
        clear_oid = "1.3.6.1.4.1.1206.4.2.11.2.5.1"  # OID for clearing requests
        console_logs = []

        if msg_type == "ClearRequest":
            msg = "[INFO] Received ClearRequest: Clearing all active requests."
            self.log(msg, tag="REQUEST")

            for req in self.active_requests.values():
                req["setOID"] = clear_oid  
                req["status"] = "pending"  # Mark as pending for sending
                req["setValue"] = (
                    req["requestIDHex"] + self.vehicle_id_to_hex(req["vehicleIDStr"]) +
                    req["classType"] + req["classLevel"] + req["priorityRequestPhase"]
                )

                msg = f"[CLEAR] RequestID={req['requestIDHex']} for VehicleID={req['vehicleIDStr']} marked for clearing."
                self.log(msg, tag="REQUEST")
            return 

        priority_list = data.get("PriorityRequestList", {})
        requestor_info = priority_list.get("requestorInfo", [])
        
        # Count existing (classType, priorityRequestPhase) in active requests
        current_counts = {}
        for req in self.active_requests.values():
            key = (req["classType"], req["priorityRequestPhase"])
            current_counts[key] = current_counts.get(key, 0) + 1

        # Build set of current request keys (triple of vehicleID, classType, phase)
        current_req_keys = set()
        for request in requestor_info:
            # Convert vehicle ID
            vehicle_id_str = str(request["vehicleID"])
            vehicle_id_hex = self.vehicle_id_to_hex(vehicle_id_str)
            requested_signal_group = request.get("requestedSignalGroup", 0)
            priority_request_phase = f"{requested_signal_group:02x}"
            vehicle_type = request.get("vehicleType", 0)
            # Use fixed class type for now
            class_type = "07"
            
            # The triple uniquely identifies a request for comparison
            current_req_keys.add((vehicle_id_str, class_type, priority_request_phase))
            
            '''
            # Check if the vehicle ID already exists in an active request
            matching_request_id = None
            for req_id, req in self.active_requests.items():
                if req["vehicleIDStr"] == vehicle_id_str:
                    if req["classType"] == class_type and req["priorityRequestPhase"] == priority_request_phase:
                        self.log(
                            f"[Update Matching] for VehicleID={vehicle_id_str}, ClassType={class_type}, Phase={priority_request_phase}, "
                            f"Matches with ID={req['requestIDHex']}, VehicleID={req['vehicleIDStr']}, ClassType={req['classType']}, Phase={req['priorityRequestPhase']}",
                            tag="REQUEST"
                        )
                        matching_request_id = req_id
                        break
                    else:
                        self.log(
                            f"[ERROR] Conflicting request for VehicleID={vehicle_id_str}: "
                            f"Existing request has ClassType={req['classType']}, Phase={req['priorityRequestPhase']}, "
                            f"but new request has ClassType={class_type}, Phase={priority_request_phase}",
                            level="ERROR", tag="REQUEST"
                        )
                        continue
            '''
            
            matching_request_id = None
            for req_id, req in self.active_requests.items():
                # 1. If VehicleID matches but ClassType does NOT, log conflict
                if req["vehicleIDStr"] == vehicle_id_str and req["classType"] != class_type:
                    self.log(
                        f"[ERROR] Conflicting class type for VehicleID={vehicle_id_str}: "
                        f"Existing ClassType={req['classType']}, New ClassType={class_type}",
                        level="ERROR", tag="REQUEST"
                    )
                    continue
                # 2. If VehicleID and ClassType BOTH match
                if req["vehicleIDStr"] == vehicle_id_str and req["classType"] == class_type:
                    if req["priorityRequestPhase"] == priority_request_phase:
                        # Exact match: update as usual
                        self.log(
                            f"[Update Matching] for VehicleID={vehicle_id_str}, ClassType={class_type}, Phase={priority_request_phase}, "
                            f"Matches with ID={req['requestIDHex']}, VehicleID={req['vehicleIDStr']}, "
                            f"ClassType={req['classType']}, Phase={req['priorityRequestPhase']}",
                            tag="REQUEST"
                        )
                        matching_request_id = req_id
                        break
                    elif req["priorityRequestPhase"] == "unknown":
                        # Phase unknown: treat as match and update phase
                        self.log(
                            f"[Phase Unknown Match] for VehicleID={vehicle_id_str}, ClassType={class_type}, "
                            f"controller had phase='unknown', updating to Phase={priority_request_phase}",
                            tag="REQUEST"
                        )
                        req["priorityRequestPhase"] = priority_request_phase
                        matching_request_id = req_id
                        break
                    # If phase does not match, no error, just continue to next

                        
            ETA = int(request.get("ETA", 0))
            ETD = int(ETA + request.get("ETA_Duration", 0))
            ETA_hex = f"{ETA:04x}"
            ETD = ETD
            ETD_hex = f"{ETD:04x}"
            
            if matching_request_id is not None:
                # Use the same request ID and send an update instead of a new set command
                matching_request = self.active_requests[matching_request_id]
                priority_request_id = matching_request["requestIDHex"]
                set_oid = update_oid  # Change OID to update process
                class_level = matching_request["classLevel"]
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
                self.log(msg, tag="REQUEST")

            else:
                set_oid = new_oid
                # Assign a new request ID
                priority_request_id = self.find_next_available_id()  # Get first available ID
                self.used_ids.add(int(priority_request_id, 16))

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

                self.active_requests[request_id_dec] = {
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
                }
                    
        # Find requests present last time but NOT this time (need to be cancelled)
        to_cancel = self.prev_req_ids - current_req_keys
        for cancel_key in to_cancel:
            vehicle_id_str, class_type, priority_request_phase = cancel_key
            for req in self.active_requests.values():
                if (req["vehicleIDStr"], req["classType"], req["priorityRequestPhase"]) == cancel_key:
                    req["setOID"] = clear_oid
                    req["status"] = "pending"
                    req["setValue"] = (
                        req["requestIDHex"] + self.vehicle_id_to_hex(req["vehicleIDStr"]) +
                        req["classType"] + req["classLevel"] + req["priorityRequestPhase"]
                    )
                    self.log(f"[AUTO-CANCEL] Auto-clearing RequestID={req['requestIDHex']} for VehicleID={vehicle_id_str}, "
                         f"ClassType={class_type}, Phase={priority_request_phase}", tag="REQUEST")
                    break      
        
        self.prev_req_ids = current_req_keys  # Update for next cycle

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
            
        for req in self.active_requests.values():
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
                
                # Send SNMP SET and log command
                self.log(f"[{action_type}] SNMP SET command: {' '.join(command)}", tag="SNMP")
                success = self.snmp_set_hex(req["setOID"], req["setValue"])
                
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
                    self.log(
                        f"[{action_type}] SNMP SET sent for RequestID={req['requestIDHex']}, "
                        f"VehicleID={req['vehicleIDStr']}, "
                        f"VehicleClassType={req['classType']}, "
                        f"VehicleClassLevel={req['classLevel']}, "
                        f"PriorityRequestPhase={req['priorityRequestPhase']}, "
                        f"ETA={req['currentETA']}, ETD={req['currentETD']}",
                        tag="SNMP"
                    )
                    req["status"] = "active"
                else:
                    self.log(f"SNMP SET failed for RequestID={req['requestIDHex']}", level="ERROR", tag="SNMP")
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
            self.log(f"SNMP SET Error: {e.stderr.strip()}", level="ERROR", tag="SNMP")
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
        self.log("=== NewSolver is now actively listening for requests and monitoring ===", tag="MONITOR")

        while True:
            console_logs = []
            # === 1. Handle new incoming UDP priority requests ===
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

                self.log("=== Received New Priority Request ===", tag="MONITOR")

                self.generate_snmp_requests(input_data)
                self.send_all_snmp_sets()

            except socket.timeout:
                pass  # No new input, continue monitoring existing requests
            
            # === 2. Re-sync active requests with the controller ===
            msg = "=== Monitoring Active Requests ==="
            console_logs.append(msg)
            print("\n", msg)

            # Print the epoch time before showing the requests
            self.log("=== Monitoring Active Requests ===", tag="MONITOR")
            epoch_time = int(time.time())
            self.log(f"Epoch Time: {epoch_time}", tag="MONITOR")

            controller_active, controller_active_ids = self.scan_controller_active_requests()
            # Only update statusOID and status for matching requests in self.active_requests.
            for req_id, controller_info in controller_active.items():
                if req_id in self.active_requests:
                    self.active_requests[req_id]["statusOID"] = controller_info["statusOID"]
                    self.active_requests[req_id]["status"] = controller_info["status"]
                else:
                    # If a request is in controller but not locally, add it (rare, but possible after reboot/desync)
                    self.active_requests[req_id] = controller_info

            # Remove requests that no longer exist in the controller
            for req_id in list(self.active_requests.keys()):
                if req_id not in controller_active_ids:
                    del self.active_requests[req_id]
            
            # Optionally update self.used_ids as well (add any not already present)
            for req_id in controller_active_ids:
                self.used_ids.add(req_id)

            # === 3. Print incomplete requests ===
            self.print_incomplete_requests()

    def print_incomplete_requests(self):
        """Print and log the status of all incomplete requests each time step."""
        if not self.active_requests:
            msg = "No incomplete requests at this moment."
            self.log(msg, tag="REQUEST")
        else:
            self.log("--- Incomplete Requests ---", tag="REQUEST")
            for req in self.active_requests.values():
                line = (
                    f"RequestID={req['requestIDHex']}, "
                    f"VehicleID={req['vehicleIDStr']}, "
                    f"VehicleClassType={req['classType']}, "
                    f"VehicleClassLevel={req['classLevel']}, "
                    f"PriorityRequestPhase={req['priorityRequestPhase']}, "
                    f"Status={req['status']}"
                )
                self.log(line, tag="REQUEST")
            self.log("---------------------------", tag="REQUEST")

if __name__ == "__main__":
    # Load configuration file
    config_file_path = "/nojournal/bin/mmitss-phase3-master-config.json"
    try:
        with open(config_file_path, 'r') as configFile:
            config = json.load(configFile)
    except Exception as e:
        # Fails before app exists, so log to a basic file or print and exit
        with open("/nojournal/bin/log-1211/monitoring_log_startup.json", "a") as f:
            import datetime, time
            f.write(json.dumps({
                "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "EpochTime": int(time.time()),
                "Level": "ERROR",
                "Tag": "STARTUP",
                "Message": f"[ERROR] Failed to load config file: {e}"
            }) + "\n")
        print(f"[ERROR] Failed to load config file: {e}")
        exit(1)

    # Attempt to extract values and start app
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
        # Log startup errors using app.log() if possible
        try:
            app.log(f"[ERROR] Missing key in configuration: {e}", level="ERROR", tag="STARTUP")
        except Exception:
            # fallback if app is not defined due to earlier crash
            with open("/nojournal/bin/log-1211/monitoring_log_startup.json", "a") as f:
                import datetime, time
                f.write(json.dumps({
                    "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "EpochTime": int(time.time()),
                    "Level": "ERROR",
                    "Tag": "STARTUP",
                    "Message": f"[ERROR] Missing key in configuration: {e}"
                }) + "\n")
        print(f"[ERROR] Missing key in configuration: {e}")

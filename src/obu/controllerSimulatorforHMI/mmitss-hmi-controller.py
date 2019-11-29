'''
**********************************************************************************
 © 2019 Arizona Board of Regents on behalf of the University of Arizona with rights
       granted for USDOT OSADP distribution with the Apache 2.0 open source license.
**********************************************************************************
  MMITSS-hmi-controller-simulator.py
  Created by: Larry Head
  University of Arizona   
  College of Engineering

  
  Operational Description:

  This application does the following tasks:
  1. Listents to port 20009 to receive updated from message transiever (remote bsm and spat data) and host vehicle (bsm, map, and priority status)
  2. Builds json representing the HMI states to send to the HMI
  3. Sends the json to the HMI
'''

import socket
import json
import time
import os

from Position3D import Position3D
from BasicVehicle import BasicVehicle


controllerIP = '127.0.0.1'
controllerPort = 20009
controller = (controllerIP, controllerPort)

hmiIP = '127.0.0.1'
hmiPort = 20010
hmi = (hmiIP, hmiPort)

bool_map = {"TRUE": True, "True": True, "FALSE": False, "False": False} # this could be come the SPaT phaseStatus data map
spat_state = {0 : "unknown", # based on the MOvementPhaseState from the SAE J2735 2016 standard - not comment in MovementPhaseState is that these are not used with UPER encoding (???)
              1 : "dark", 
              2 : "stop-Then-Proceed", # flashing red (flashing Red ball)
              3 : "stop-And-Remain", # red light (Red ball) [Don't walk]
              4 : "pre-Movement", # not used in US
              5 : "permissive-Movement-Allowed", # permissive green (Green ball)
              6 : "protected-Movement-Allowed",  # protected green (e.g. left turn arrow) - Green Arrow (direction?) [also walk]
              7 : "permissive-clearance", # permissive yellow (clear intersection) - Yellow 
              8 : "protected-clearance", # protected yellow (clear intersection) - Yellow arrow  [ also ped clear= Flashing Don;t Walk]
              9 : "caution-Conflicting-Traffic", # flashing yellow (yield)
              } 

spat_signal_head = {"stop-And-Remain" : "red", "stop-Then-Proceed" : "red_flash", "protected-Movement-Allowed" : "green", "permissive-clearance" : "yellow", "protected-clearance" : "yellow",  "dark" : "dark"}
phase_status_map = { "dark" : '-', "red" : "R", "red_flash" : "F", "yellow" : "Y", "green" : "G"}
ped_status_map = { "dark" : "-", "red_flash" : '-', "red" : "DW", "yellow": "PC", "green" : "W"}

priority_responseStatus = {0 : "unknown", 
                           1 : "requested",
                           2 : "processing",
                           3 : "watchOtherTraffic",
                           4 : "granted",
                           5 : "rejected",
                           6 : "maxPresence",
                           7 : "reserviceLocked"}

basicVehicleRoles = {0 : "basicVehicle",
                    9 : "truck",
                    13 : "ev-fire",
                    16 : "transit"}

def phase_status_state(phase_status):
    for key in phase_status:
        if phase_status[key] == True:
            return key

def signal_head(phase_status):
    current_phase_status = {"red" : False, "red_flash" : False, "yellow" : False, "green" : False, "green_arrow" : False, "minEndTime" : phase_status["minEndTime"],
                            "maxEndTime" : phase_status["maxEndTime"], "dark" : False}
    current_phase_status[spat_signal_head[phase_status['currState']]] = True
    return current_phase_status

def manageRemoteVehicleList(remoteBSMjson, remoteVehicleList) :
    # get the id of the new BSM data
    vehicleID = remoteBSMjson["BasicVehicle"]["temporaryID"]
    vehicleInformation = remoteBSMjson["BasicVehicle"]
    vehicleUpdateTime = time.time()
    # if there are no vehicles in the list, add the current vehicle 
    if len(remoteVehicleList) == 0 : 
        remoteVehicleList.append({"vehicleID" : vehicleID, "vehicleInformation" : {"BasicVehicle" : vehicleInformation}, "vehicleUpdateTime" : vehicleUpdateTime})
        return remoteVehicleList
    # update existing vehicles
    rv_updated = False
    for rv in remoteVehicleList :
        if rv["vehicleID"] == vehicleID :
            print("rv data: ", rv["vehicleInformation"])
            rv["vehicleInformation"] = {"BasicVehicle" : vehicleInformation}
            rv["vehicleUpdateTime"] = vehicleUpdateTime
            rv_updated = True
    if not rv_updated : #vehicle wasn't in the list of active vehicles, add it to the list
        remoteVehicleList.append({"vehicleID" : vehicleID, "vehicleInformation" : {"BasicVehicle" : vehicleInformation}, "vehicleUpdateTime" : vehicleUpdateTime})
    return remoteVehicleList

def removeOldRemoteVehicles(remoteVehicleList) :
    tick = time.time()
    newRemoteVehicleList = [rv for rv in remoteVehicleList if not ((tick - rv["vehicleUpdateTime"]) > 0.5)]
    return newRemoteVehicleList

    
# initialize all the data
#host vehicle data
secMark = 0
hv_tempID = int(0)
hv_vehicleType = " "
hv_latitude_DecimalDegree= round(0.0, 8)
hv_longitude_DecimalDegree= round(0.0, 8)
hv_elevation_Meter= round(0.0, 1)
hv_heading_Degree= round(0.0, 4)
hv_speed_Meterpersecond= float(0)
hv_speed_mph= int((float(hv_speed_Meterpersecond) * 2.23694))
hv_currentLane = int(0)
hv_currentLaneSignalGroup = int(0)
onMAP = False
requestSent = False
availableMaps = []
activeRequestTable = []

#remote vehicle data
rv_tempID = int(0)
rv_vehicleType = " "
rv_latitude_DecimalDegree= round(0.0, 8)
rv_longitude_DecimalDegree= round(0.0, 8)
rv_elevation_Meter= round(0.0, 1)
rv_heading_Degree= round(0.0, 4)
rv_speed_Meterpersecond= float(0.0)
rv_speed_mph= int((float(rv_speed_Meterpersecond) * 2.23694))
remoteVehicleList = []

#SPaT data
spat_regionalID = int(0)
spat_intersectionID = int(0)
spat_msgCnt = int(0)
spat_minutesOfYear = int(0)
spat_msOfMinute = int(0)
spat_status = int(0)
phase_table = []
current_phase_status = {"red" : False, "red_flash" : False, "yellow" : False, "green" : False, "green_arrow" : False, "minEndTime" : 999.9,
                            "maxEndTime" : 999.9, "dark" : True}
phase_table = []
for phase in range(0,8) :
    phase_table.append({"phase" : phase, 
                            "phase_status" : '-', 
                            "ped_status" : '-'})

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the created socket to the server information.
s.bind((controller))


while True:
    
    #receive data from mmitss components
    line, addr = s.recvfrom(4096) 
    line = line.decode()
    sourceIP, sourcePort = addr

    if sourcePort == 10004 :
        # process the remote vehicle and SPaT data
        print('remote bsm and spat data', line)

        # load the json
        remoteInterfacejson = json.loads(line)

        if remoteInterfacejson["MsgType"] =='BSM' :
            #translate remote basic vehicle data
            print(' BSM data received')
            manageRemoteVehicleList(remoteInterfacejson, remoteVehicleList)
            #remoteVehicles.append(remoteInterfacejson["BSM"]) #how do I want to deal with a collection of remote vehicle data???? Currently, they get reported when host vehicle gets updated

        elif remoteInterfacejson["MsgType"] == 'SPaT' :
            #check to make sure it is spat
            print('SPaT data received')
            SPaT_data = remoteInterfacejson
            SPaT = []
            pedSPaT = []
            spat_regionalID = int(SPaT_data["Spat"]["IntersectionState"]["regionalID"])
            spat_intersectionID = int(SPaT_data["Spat"]["IntersectionState"]["intersectionID"])
            spat_msgCnt = int(SPaT_data["Spat"]["msgCnt"])
            spat_minutesOfYear = int(SPaT_data["Spat"]["minuteOfYear"])
            spat_msOfMinute = int(SPaT_data["Spat"]["msOfMinute"])
            spat_status = int(SPaT_data["Spat"]["status"])
            SPaT = SPaT_data["Spat"]["phaseState"]
            pedSPaT = SPaT_data["Spat"]["pedPhaseState"]

            # don't send raw spat data to hmi, send current phase state in red, yellow, green as True/False
            current_phase_status = signal_head(SPaT[hv_currentLaneSignalGroup])

            # add the 8-phase signal and ped status data
            phase_table = []
            for phase in range(0,8):
                phase_state = signal_head(SPaT[phase])
                ped_state = signal_head(pedSPaT[phase])
                phase_table.append({"phase" : phase, 
                                    "phase_status" : phase_status_map[phase_status_state(phase_state)], 
                                    "ped_status" : ped_status_map[phase_status_state(ped_state)]})

        else : 
            print('ERROR: remote vehicle or SPaT data expected')

        #publish the data to the HMI


    elif sourcePort == 20004 :

        print('host vehicle and infrastructure data', line)
        
        # load the json
        hostAndInfrastructureData = json.loads(line)

        # process the host vehicle and infrastructure data
        hv_tempID = int(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["vehicleID"])
        hv_vehicleType = hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["vehicleType"]
        hv_latitude_DecimalDegree= round(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["position"]["latitude_DecimalDegree"], 8)
        hv_longitude_DecimalDegree= round(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["position"]["longitude_DecimalDegree"], 8)
        hv_elevation_Meter= round(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["position"]["elevation_Meter"], 1)
        hv_heading_Degree= round(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["heading_Degree"], 4)
        hv_speed_Meterpersecond= float(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["speed_MeterPerSecond"])
        hv_speed_mph= int((float(hv_speed_Meterpersecond) * 2.23694))
    
        # Create a Basic Vehicle that represents the host vehicle
        hv_position = Position3D(hv_latitude_DecimalDegree, hv_longitude_DecimalDegree, hv_elevation_Meter)
        hostVehicle = BasicVehicle(hv_tempID, secMark, hv_position, hv_speed_mph, hv_heading_Degree, hv_vehicleType)

        #need to acquire current lane and current lane signal group
        hv_currentLane = int(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["laneID"])
        hv_currentLaneSignalGroup = int(hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["signalGroup"])
        onMAP = hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["priorityStatus"]["OnMAP"]

        requestSent = hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["hostVehicle"]["priorityStatus"]["requestSent"]

        availableMaps = hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["infrastructure"]["availableMaps"]
        
        activeRequestTable = hostAndInfrastructureData["PriorityRequestGeneratorStatus"]["infrastructure"]["activeRequestTable"]

        # prepare the list of remote vehicles for display
        remoteVehicleList = removeOldRemoteVehicles(remoteVehicleList)
        remoteVehicles = []
        for rv in remoteVehicleList :
            remoteVehicles.append(rv["vehicleInformation"])


        #update the HMI with new data (assuming the 10 Hz host vehilce data is the update trigger)
        interfaceJsonString = json.dumps({
        "mmitss_hmi_interface":
        {
            "hostVehicle" :
            {
                "secMark_Second" : secMark,
                "temporaryID" : hv_tempID,
                "vehicleType" : hv_vehicleType,
                "position" :
                {
                    "elevation_Meter" : hv_elevation_Meter,
                    "latitude_DecimalDegree" : hv_latitude_DecimalDegree,
                    "longitude_DecimalDegree" : hv_longitude_DecimalDegree
                },
                "heading_Degree" : hv_heading_Degree,
                "speed_mph": hv_speed_mph,
                "lane": hv_currentLane, 
                "signalGroup" : hv_currentLaneSignalGroup,
                "priority" : {"OnMAP" : onMAP, "requestSent" : requestSent}
            },
            "remoteVehicles" :
                remoteVehicles,
            "infrastructure": 
            {
                "availableMaps": availableMaps,
                "currentPhase" : current_phase_status, # data for signal head, min, and max
                "phaseStates" : phase_table, #data for 8-phase display table
                "activeRequestTable" : activeRequestTable
            },
        }
        })
        s.sendto(interfaceJsonString.encode(),hmi)
        print('update hmi: ', interfaceJsonString)

    else :
        print('ERROR: data received from unknown source')
    
s.close() 
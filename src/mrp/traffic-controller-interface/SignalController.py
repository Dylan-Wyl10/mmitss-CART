"""
***************************************************************************************

 © 2019 Arizona Board of Regents on behalf of the University of Arizona with rights
       granted for USDOT OSADP distribution with the Apache 2.0 open source license.

***************************************************************************************

SignalController.py
Created by: Niraj Vasant Altekar
University of Arizona   
College of Engineering

This code was developed under the supervision of Professor Larry Head
in the Systems and Industrial Engineering Department.

***************************************************************************************

Description:
------------
This class encapsulates all methods that interacti with the signal controller. The 
methods available from this class facilitate the following:
(1) Enable broadcast of SPAT blob
(2) Control phases in the signal controller
(3) Send information about current and next phases to the requestor via a combination 
of calls to Snmp::getValue funtion and listening for information from MapSpatBroadcaster
(4) Store and maintain the current active timing plan information.

***************************************************************************************
"""

import datetime
import time
import socket
import json
import StandardMib
import importlib.util
from Command import Command
from Snmp import Snmp

class SignalController:
    """
    provides methods to interact with the signal controller.
    """

    def __init__(self): # Check if there exists an NTCIP object to read it through SNMP.
        
                
        # Read the config file and store the configuration in an JSON object:
        configFile = open("/nojournal/bin/mmitss-phase3-master-config.json", 'r')
        config = (json.load(configFile))

        # Close the config file:
        configFile.close()

        # Create a tuple to store the communication address of the traffic signal controller:
        signalControllerIp = config["SignalController"]["IpAddress"]
        signalControllerNtcipPort = config["SignalController"]["NtcipPort"]
        self.signalController_commInfo = (signalControllerIp, signalControllerNtcipPort)

        self.vendor = config["SignalController"]["Vendor"].lower()

        self.timingPlanMibName = (config["SignalController"]["TimingPlanMib"])
        timingPlanMibFileName = self.timingPlanMibName

        if self.timingPlanMibName.lower() != "standardmib":
            # Read the filename of the Mib that can be used to extract timing plan parameters.
            spec = importlib.util.spec_from_file_location(self.timingPlanMibName, timingPlanMibFileName)
            self.timingPlanMib = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.timingPlanMib)
        else: self.timingPlanMib = StandardMib

        # Read the arguments into local variables:
        self.snmp = Snmp()
        self.timingPlanUpdateInterval_sec = config["SignalController"]["TimingPlanUpdateInterval_sec"]
        self.ntcipBackupTime_sec = int(self.snmp.getValue(StandardMib.NTCIP_UNIT_BACKUP_TIME))
        
        # Create a tuple to store the communication address of the socket that listens for Current and Next Phases info sent by the MapSpatBroadcaster:
        mrpIp = config["HostIp"]
        currPhaseListenerPort = config["PortNumber"]["TrafficControllerCurrPhaseListener"]
        self.currPhaseListenerAddress = (mrpIp, currPhaseListenerPort)

        # Create a tuple to store the address of consumer of the timing plan.
        solverPort = config["PortNumber"]["PrioritySolver"]
        self.solverAddress = (mrpIp, solverPort)

        # Create a tuple to store the address of timing plan sender
        timingPlanSenderPort = config["PortNumber"]["TrafficControllerTimingPlanSender"]
        self.timingPlanSenderAddress = (mrpIp, timingPlanSenderPort)

        # Initialize current timing plan ID and corresponding JSON string
        self.currentTimingPlanId = 0
        self.currentTimingPlanJson = ""
        
        # Read the currently active timing plan and store it into a JSON string
        self.updateAndSendActiveTimingPlan()

    ######################## Definition End: __init__(self, snmp:Snmp) ########################

    def getPhaseControl(self, action:int) -> int:
        """
        returns the integer representation of bit-string denoting which phases are currently executing 
        the action.
        
        Arguments:
        ----------
            (1) Action ID:
                    The action can be chosen from the command class. Available actions are:
                    CALL_VEH_PHASES, CALL_PED_PHASES, FORCEOFF_PHASES, HOLD_VEH_PHASES, OMIT_VEH_PHASES, 
                    OMIT_PED_PHASES. The mapping of actions to integer is available in Command class. 
        
        Returns:
        --------
            the value (representing the bit-string that denotes the phases that are executing the required action) 
            obtained from the snmp.getValue(action:int) function.
        """

        # Create a dummy command to get the enumerations corresponding to each phase control action
        command = Command(0,0,0,0)

        if action == command.CALL_VEH_PHASES:
            value = int(self.snmp.getValue(StandardMib.PHASE_CONTROL_VEHCALL))
        elif action == command.CALL_PED_PHASES:
            value = int(self.snmp.getValue(StandardMib.PHASE_CONTROL_PEDCALL))
        elif action == command.FORCEOFF_PHASES:
            value = int(self.snmp.getValue(StandardMib.PHASE_CONTROL_FORCEOFF))
        elif action == command.HOLD_VEH_PHASES:
            value = int(self.snmp.getValue(StandardMib.PHASE_CONTROL_HOLD))
        elif action == command.OMIT_VEH_PHASES:
            value = int(self.snmp.getValue(StandardMib.PHASE_CONTROL_VEH_OMIT))
        elif action == command.OMIT_PED_PHASES:
            value = int(self.snmp.getValue(StandardMib.PHASE_CONTROL_PED_OMIT))
        
        return value

    def setPhaseControl(self, action:int, phases:int, scheduleReceiptTime:float):
        """
        sets the NTCIP phase control in the signal controller. 

        Arguments:
        ----------
            (1) Action ID:
                    The action can be chosen from the command class. Available actions are:
                    CALL_VEH_PHASES, CALL_PED_PHASES, FORCEOFF_PHASES, HOLD_VEH_PHASES, OMIT_VEH_PHASES, 
                    OMIT_PED_PHASES. The mapping of actions to integer is available in Command class. 
            (2) Phases:
                    The phases parameter is an integer representation of a bitstring for which a phase 
                    control needs to be applied. For example, for placing a vehicle call on all phases, 
                    the bit string would be (11111111), whose integer representation is 255.
            (3) Schedule Receipt Time:
                    The (epoch) time when the schedule was received from the Solver. The execution times will be 
                    relative to this time.
        """
        command = Command(0,0,0,0)
        phasesStr = str(f'{phases:08b}')[::-1]
        phaseList = []
        for i in range(len(phasesStr)):
            if phasesStr[i] == str(1):
                phaseList = phaseList + [i+1]
        
        if action == command.CALL_VEH_PHASES:
            self.snmp.setValue(StandardMib.PHASE_CONTROL_VEHCALL, phases)
            print("Veh-CALL " + str(phaseList) + " after " + str(round((time.time() - scheduleReceiptTime),2)) + " seconds")
        
        elif action == command.CALL_PED_PHASES:
            self.snmp.setValue(StandardMib.PHASE_CONTROL_PEDCALL, phases)
            print("Ped-CALL " + str(phaseList) + " after " + str(round((time.time() - scheduleReceiptTime),2)) + " seconds")

        elif action == command.FORCEOFF_PHASES:
            self.snmp.setValue(StandardMib.PHASE_CONTROL_FORCEOFF, phases)
            print("FORCEOFF " + str(phaseList) + " after " + str(round((time.time() - scheduleReceiptTime),2)) + " seconds")

        elif action == command.HOLD_VEH_PHASES:
            self.snmp.setValue(StandardMib.PHASE_CONTROL_HOLD, phases)
            print("HOLD " + str(phaseList) + " after " + str(round((time.time() - scheduleReceiptTime),2)) + " seconds")

        elif action == command.OMIT_VEH_PHASES:
            self.snmp.setValue(StandardMib.PHASE_CONTROL_VEH_OMIT, phases)
            print("Veh-OMIT " + str(phaseList) + " after " + str(round((time.time() - scheduleReceiptTime),2)) + " seconds")

        elif action == command.OMIT_PED_PHASES:
            self.snmp.setValue(StandardMib.PHASE_CONTROL_PED_OMIT, phases)
            print("Ped-OMIT " + str(phaseList) + " after " + str(round((time.time() - scheduleReceiptTime),2)) + " seconds")                   
        else: 
            print("Invalid action requested")
    ######################## Definition End: phaseControl(self, action, phases) ########################

    def sendCurrentAndNextPhasesDict(self, requesterAddress:tuple):
        """
        sends a dictionary containing lists of current and next phases to the requestor

        This function does three tasks:
        (1) Open a UDP socket at a port where MapSpatBroadcaster sends the information about current phases.
        (2) If the current phase is not in Green state (i.e. either red or yellow), this function calls the 
        getNextPhaseDict function. Else, next phases are set to 0.
        (3) Formulates a json string comprising the information about current phases and next phases and sends it
        to the requestor.

        Arguments:
        ----------
            (1) requestorAddress: 
                    This is a tuple containing IP address and port of the client 
                    who request the information about current and next phases.
        """


        def getNextPhasesDict() -> dict:
            """
            requests the "next phases" in the controller through an Snmp::getValue method.
                        
            Returns:
            --------
                A dictionary containing the list of next phases.
            """

            nextPhasesInt = int(self.snmp.getValue(StandardMib.PHASE_GROUP_STATUS_NEXT))
            print("Current next phases are" + str(nextPhasesInt))
            nextPhasesStr = str(f'{(nextPhasesInt):08b}')[::-1]
            
            nextPhasesList = [0,0]
            # Identify first next phase
            for i in range(0,8):
                if nextPhasesStr[i] == "1":
                    nextPhasesList[0] = i+1
                    break
            # Identify second next phase
            for i in range(0,8):
                if nextPhasesStr[i] == "1":
                    nextPhasesList[1] = i+1

            if nextPhasesList[0] == nextPhasesList[1]:
                nextPhasesDict= {"nextPhases":[nextPhasesList[0]]}
            else:
                nextPhasesDict= {"nextPhases":[nextPhasesList[0], nextPhasesList[1]]}

            return nextPhasesDict
        ######################## Definition End: getNextPhasesDict() ########################

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(self.currPhaseListenerAddress)
        data, addr = s.recvfrom(1024)
        print("Received CurrPhaseStatus from MapSpatBroadcaster: " + str(data.decode()))

        currentPhasesDict = json.loads(data.decode())

        if ((currentPhasesDict["currentPhases"][0]["State"]=="green") and (currentPhasesDict["currentPhases"][1]["State"]=="green")):
            nextPhasesDict= {"nextPhases":[0]}
        else:
            nextPhasesDict = getNextPhasesDict()

        currentAndNextPhasesDict = currentPhasesDict
        currentAndNextPhasesDict["MsgType"] = "CurrNextPhaseStatus"
        currentAndNextPhasesDict["nextPhases"] = nextPhasesDict["nextPhases"]
        currentAneNextPhasesJson = json.dumps(currentAndNextPhasesDict)
        
        s.sendto(currentAneNextPhasesJson.encode(), requesterAddress)
        print("Sent curr and NextPhasestatus to solver at time " + str(time.time()) +str(currentAneNextPhasesJson))
        s.close()
    ######################## Definition End: sendCurrentAndNextPhasesDict(self, currPhaseListenerAddress:tuple, requesterAddress:tuple): ########################

    def updateAndSendActiveTimingPlan(self):
        """
        updates the active timing plan and sends the active timing plan to PriorityRequestSolver.

        For Econolite signal controllers, this function first checks the ID of currently active timing plan, through Snmp::getValue function.
        If the ID does not match the ID of the timing plan currently stored in the class attribute, 
        the function updates the timing plan stored in the class attribute, via different calls to Snmp::getValue function.

        For other signal controllers using the standard MIB, this function does the same task but with different OIDs. 
        Note that for in the standard MIB, we can get information only about the timing plan # 1.
        """
        
        if self.vendor.lower()=="econolite" and self.timingPlanMibName.lower()=="/nojournal/bin/econolitemib.py": # This block is valid for Econolite only:
            def getActiveTimingPlanId():
                activeTimingPlanId = int(self.snmp.getValue(self.timingPlanMib.CUR_TIMING_PLAN))
                return activeTimingPlanId
            
            def getPhaseParameterPhaseNumber(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PHASE_NUMBER) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterPedWalk(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PEDWALK) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterPedClear(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PEDCLEAR) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterMinGreen(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_MIN_GRN) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterPassage(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PASSAGE) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))*0.1
                return phaseParameter

            def getPhaseParameterMaxGreen(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_MAX_GRN) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterYellowChange(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_YELLOW_CHANGE) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))*0.1
                return phaseParameter

            def getPhaseParameterRedClear(activeTimingPlanId:int):
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_RED_CLR) + '.' + str(activeTimingPlanId) + "." + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))*0.1
                return phaseParameter

            def getPhaseParameterRing():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (StandardMib.PHASE_PARAMETERS_RING) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            activeTimingPlanId = getActiveTimingPlanId()
            if activeTimingPlanId != self.currentTimingPlanId:
                self.currentTimingPlanId = activeTimingPlanId
                activeTimingPlan =  dict({
                                    "MsgType": "ActiveTimingPlan",
                                    "TimingPlan":{
                                    "NoOfPhase": 8,
                                    "PhaseNumber": getPhaseParameterPhaseNumber(activeTimingPlanId),
                                    "PedWalk": getPhaseParameterPedWalk(activeTimingPlanId),
                                    "PedClear": getPhaseParameterPedClear(activeTimingPlanId),
                                    "MinGreen": getPhaseParameterMinGreen(activeTimingPlanId),
                                    "Passage": getPhaseParameterPassage(activeTimingPlanId),
                                    "MaxGreen": getPhaseParameterMaxGreen(activeTimingPlanId),
                                    "YellowChange": getPhaseParameterYellowChange(activeTimingPlanId),
                                    "RedClear": getPhaseParameterRedClear(activeTimingPlanId),
                                    "PhaseRing": getPhaseParameterRing(),
                }})
                self.currentTimingPlanJson =  json.dumps(activeTimingPlan)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(self.timingPlanSenderAddress)
                s.sendto((self.currentTimingPlanJson).encode(), self.solverAddress)
                s.close()
                print("Detected a new timing plan - updated and sent (to solver) the local timing plan at time:" + str(time.time()))
                print(self.currentTimingPlanJson)

        else:
            def getPhaseParameterPhaseNumber():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PHASE_NUMBER) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterPedWalk():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PEDWALK) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterPedClear():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PEDCLEAR) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterMinGreen():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_MIN_GRN) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterPassage():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_PASSAGE) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))*0.1
                return phaseParameter

            def getPhaseParameterMaxGreen():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_MAX_GRN) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            def getPhaseParameterYellowChange():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_YELLOW_CHANGE) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))*0.1
                return phaseParameter

            def getPhaseParameterRedClear():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (self.timingPlanMib.PHASE_PARAMETERS_RED_CLR) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))*0.1
                return phaseParameter

            def getPhaseParameterRing():
                phaseParameter = [0 for x in range (0,8)]
                for i in range(0,8):
                    oid = (StandardMib.PHASE_PARAMETERS_RING) + str(i+1)
                    phaseParameter[i] = int(self.snmp.getValue(oid))
                return phaseParameter

            activeTimingPlan =  dict({
                                "MsgType": "ActiveTimingPlan",
                                "TimingPlan":{
                                "NoOfPhase": 8,
                                "PhaseNumber": getPhaseParameterPhaseNumber(),
                                "PedWalk": getPhaseParameterPedWalk(),
                                "PedClear": getPhaseParameterPedClear(),
                                "MinGreen": getPhaseParameterMinGreen(),
                                "Passage": getPhaseParameterPassage(),
                                "MaxGreen": getPhaseParameterMaxGreen(),
                                "YellowChange": getPhaseParameterYellowChange(),
                                "RedClear": getPhaseParameterRedClear(),
                                "PhaseRing": getPhaseParameterRing(),
            }})
            self.currentTimingPlanJson =  json.dumps(activeTimingPlan)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(self.timingPlanSenderAddress)
            s.sendto((self.currentTimingPlanJson).encode(), self.solverAddress)
            s.close()
            print("Detected a new timing plan - updated and sent (to solver) the local timing plan at time:" + str(time.time()))
            print(self.currentTimingPlanJson)
            
    ######################## Definition End: updateActiveTimingPlan(self) ########################


'''##############################################
                   Unit testing
##############################################'''
if __name__ == "__main__":

    # Create an object of SignalController class
    controller = SignalController()
    
    requestTime = time.time()
    # controller.updateAndSendActiveTimingPlan()
    # leadTime = time.time()-requestTime
    # print("New timing plan acquired in:" + str(round(leadTime,4)) + " seconds")
    # print(controller.currentTimingPlanJson)
    # Write more test cases - active timing plan

"""
***************************************************************************************

 © 2019 Arizona Board of Regents on behalf of the University of Arizona with rights
       granted for USDOT OSADP distribution with the Apache 2.0 open source license.

***************************************************************************************

Snmp.py
Created by: Niraj Vasant Altekar
University of Arizona   
College of Engineering

This code was developed under the supervision of Professor Larry Head
in the Systems and Industrial Engineering Department.

***************************************************************************************

Description:
------------
This class provides methods that interface with the SnmpEngine.

***************************************************************************************
"""

import socket
import json

class Snmp:
    """
    provides methods to interface with the SnmpEngine
    """
    
    def __init__(self):
        """
        establishes a socket for interaction with map-engine.

        The information required for establishing the socket is extracted from the 
        configuration file.
        """

        configFile = open("/nojournal/bin/mmitss-phase3-master-config.json", 'r')
        config = (json.load(configFile))
        # Close the config file:
        configFile.close()

        # Open a socket and bind it to the IP and port dedicated for this application:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((config["HostIp"], config["PortNumber"]["SnmpEngineInterface"]))

        self.snmpEngineCommInfo = (config["HostIp"],config["PortNumber"]["SnmpEngine"])

    def getValue(self, oid:str) -> int:
        """
        sends a "get" request to the SnmpEngine for the OID provided in argument and returns the response

        Arguments: 
        ----------
            OID:
                An SNMP-OID from the standard (or vendor specific) MIB 
                for which the "get" request needs to be placed.
            
        Returns:
        --------
            the integer value received in the response from the SNMP Engine.
        """

        snmpGetRequestJson = json.dumps({"MsgType":"SnmpGetRequest", "OID":oid})
        self.s.sendto(snmpGetRequestJson.encode(), self.snmpEngineCommInfo)
        data, address = self.s.recvfrom(1024)
        snmpGetResponseJson = json.loads(data.decode())
        
        return snmpGetResponseJson["Value"]

    def setValue(self, oid:str, value:int):
        """
        sends a "set" request to the SnmpEngine for the OID provided in argument

        Arguments:
        ----------
            (1) OID:
                    An SNMP-OID from the standard (or vendor specific) MIB 
                    for which the "set" request needs to be placed.
            (2) Value:
                    An integer value that needs to be set for the provided oid.
        """

        snmpSetRequestJson = json.dumps({"MsgType":"SnmpSetRequest", "OID":oid, "Value":value})
        self.s.sendto(snmpSetRequestJson.encode(), self.snmpEngineCommInfo)
        

if __name__ == "__main__":

    snmp = Snmp()
    import time

    requestTime = time.time()
    print("Original value: " + str(snmp.getValue( "1.3.6.1.4.1.1206.3.5.2.9.44.1.1")))
    deliveryTime = time.time()
    leadTime = deliveryTime - requestTime
    print("Received in " + str(leadTime) + " Seconds" )

    time.sleep(0.1)
    snmp.setValue( "1.3.6.1.4.1.1206.3.5.2.9.44.1.1", 6)
    time.sleep(0.1)

    requestTime = time.time()
    print("New value: " + str(snmp.getValue( "1.3.6.1.4.1.1206.3.5.2.9.44.1.1")))
    deliveryTime = time.time()
    leadTime = deliveryTime - requestTime
    print("Received in " + str(leadTime) + " Seconds" )

    
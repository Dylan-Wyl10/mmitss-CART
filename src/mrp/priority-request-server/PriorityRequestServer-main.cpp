/*
**********************************************************************************
 © 2019 Arizona Board of Regents on behalf of the University of Arizona with rights
       granted for USDOT OSADP distribution with the Apache 2.0 open source license.
**********************************************************************************
  main.cpp
  Created by: Debashis Das
  University of Arizona   
  College of Engineering
  This code was developed under the supervision of Professor Larry Head
  in the Systems and Industrial Engineering Department.
  Revision History:
  1. This script is the demonstration of Prioririty Request Server API.
*/

#include <iostream>
#include <fstream>
#include "PriorityRequestServer.h"
#include <UdpSocket.h>
#include "msgEnum.h"
#include "json/json.h"

int main()
{
    Json::Value jsonObject;
    std::ifstream configJson("/nojournal/bin/mmitss-phase3-master-config.json");
    string configJsonString((std::istreambuf_iterator<char>(configJson)), std::istreambuf_iterator<char>());
    Json::CharReaderBuilder builder;
    Json::CharReader * reader = builder.newCharReader();
    std::string errors{};
    reader->parse(configJsonString.c_str(), configJsonString.c_str() + configJsonString.size(), &jsonObject, &errors);        
    delete reader;

    PriorityRequestServer PRS;
    SignalRequest signalRequest;
    SignalStatus signalStatus;

    UdpSocket PRSSocket(static_cast<short unsigned int>(jsonObject["PortNumber"]["PriorityRequestServer"].asInt()), 1, 0);
    const int ssmReceiverPortNo = static_cast<short unsigned int>(jsonObject["PortNumber"]["MessageTransceiver"]["MessageEncoder"].asInt());
    const int solverPortNo = static_cast<short unsigned int>(jsonObject["PortNumber"]["PrioritySolver"].asInt());
    const int messageDistributorPortNo = static_cast<short unsigned int>(jsonObject["PortNumber"]["MessageDistributor"].asInt());
    const int dataCollectorPortNo = static_cast<short unsigned int>(jsonObject["PortNumber"]["DataCollector"].asInt());
   
    char receiveBuffer[15360];

    const string LOCALHOST = jsonObject["HostIp"].asString();
    const string messageDistributorIP = jsonObject["MessageDistributorIP"].asString();

    int msgType{};
    bool timedOutOccur{};
    string ssmJsonString{};
    string solverJsonString{};
    string systemPerformanceDataCollectorJsonString{};

    while (true)
    {
        timedOutOccur = PRSSocket.receiveData(receiveBuffer, sizeof(receiveBuffer));

        if (timedOutOccur == false)
        {
            string receivedJsonString(receiveBuffer);
            msgType = PRS.getMessageType(receivedJsonString);

            if (msgType == MsgEnum::DSRCmsgID_srm)
            {
                signalRequest.json2SignalRequest(receivedJsonString);
                PRS.manageSignalRequestTable(signalRequest);
            }

            else if (msgType == static_cast<int>(msgType::coordinationRequest))
                PRS.manageCoordinationRequest(receivedJsonString);

            PRS.loggingData(receivedJsonString, "received");
            ssmJsonString = PRS.createSSMJsonString(signalStatus);
            PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(ssmReceiverPortNo), ssmJsonString);
            PRSSocket.sendData(messageDistributorIP, static_cast<short unsigned int>(messageDistributorPortNo), ssmJsonString);
            PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), ssmJsonString);
            solverJsonString = PRS.createJsonStringForPrioritySolver();
            PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(solverPortNo), solverJsonString);
            PRS.printActiveRequestTable();
        }

        else
        {
            /* 
	            - Delete vehicle info from Active Request Table if Infrustracture doesn't receive and SRM for predefined time
                - After the request, if Active request table is empty then send clear request message to PRSolver
            */
            if (PRS.checkTimedOutRequestDeletingRequirement() == true)
            {
                solverJsonString = PRS.createJsonStringForPrioritySolver();
                PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(solverPortNo), solverJsonString);
                PRS.printActiveRequestTable();
            }
            
            if (PRS.sendClearRequest() == true)
            {
                solverJsonString = PRS.createJsonStringForPrioritySolver();
                PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(solverPortNo), solverJsonString);
            }
        
            if(PRS.sendSystemPerformanceDataLog()== true)
            {
                systemPerformanceDataCollectorJsonString = PRS.createJsonStringForSystemPerformanceDataLog();
                PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), systemPerformanceDataCollectorJsonString);
            }

            if (PRS.updateETA() == true)
            {
                ssmJsonString = PRS.createSSMJsonString(signalStatus);                
                PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(ssmReceiverPortNo), ssmJsonString);
                PRSSocket.sendData(messageDistributorIP, static_cast<short unsigned int>(messageDistributorPortNo), ssmJsonString);
                PRSSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), ssmJsonString);
            }
        }
    }
    PRSSocket.closeSocket();
    return 0;
}
#include "../TransceiverDecoder.h"
#include <iostream>
#include <fstream>
#include <UdpSocket.h>
#include "json/json.h"
#include "msgEnum.h"

int main()
{
    Json::Value jsonObject_config;
    std::ifstream configJson("/nojournal/bin/mmitss-phase3-master-config.json");
    string configJsonString((std::istreambuf_iterator<char>(configJson)), std::istreambuf_iterator<char>());
    Json::CharReaderBuilder builder;
    Json::CharReader * reader = builder.newCharReader();
    string errors{};
    reader->parse(configJsonString.c_str(), configJsonString.c_str() + configJsonString.size(), &jsonObject_config, &errors);        
    delete reader;

    TransceiverDecoder decoder;
    UdpSocket decoderSocket(static_cast<short unsigned int>(jsonObject_config["PortNumber"]["MessageTransceiver"]["MessageDecoder"].asInt()));
    const string LOCALHOST = jsonObject_config["HostIp"].asString();
    const string HMIControllerIP = jsonObject_config["HMIControllerIP"].asString();
    const string messageDistributorIP = jsonObject_config["MessageDistributorIP"].asString();

    const bool peerDataDecoding = jsonObject_config["PeerDataDecoding"].asBool();

    const int dataCollectorPortNo = (jsonObject_config["PortNumber"]["DataCollector"]).asInt();
    const int mapReceiverPortNo = (jsonObject_config["PortNumber"]["PriorityRequestGenerator"]).asInt();
    const int srmReceiverPortNo = (jsonObject_config["PortNumber"]["PriorityRequestServer"]).asInt();
    const int vehicleHmiPortNo = (jsonObject_config["PortNumber"]["HMIController"]).asInt();
    const int ssmReceiverPortNo = (jsonObject_config["PortNumber"]["PriorityRequestGenerator"]).asInt();
    const int trajectoryAwarePortNo = (jsonObject_config["PortNumber"]["TrajectoryAware"]).asInt();
    const int messageDistributorPort = (jsonObject_config["PortNumber"]["MessageDistributor"]).asInt();

    string receivedPayload{};
    string extractedPayload{};
    string applicationPlatform = decoder.getApplicationPlatform();
    int msgType{};
    double currentTime{};

    while (true)
    {
        receivedPayload = decoderSocket.receivePayloadHexString();
        std::cout << "Received payload is: " << receivedPayload << std::endl;
        size_t pos = receivedPayload.find("001");

        // 20240628 YW: update the logic for header issues for Danlaw device
        size_t pos_bsm = receivedPayload.find("0014");
        size_t pos_srm1 = receivedPayload.find("001d");
        size_t pos_srm2 = receivedPaylaod.find("001D");
        size_t pos_map = receivedPayload.find("0012");

        if (pos_bsm != string::npos)
        {
            pos = pos_bsm;
        }
        else if (pos_srm1 != string::npos)
        {
            pos = pos_srm1;
        }
        else if (pos_srm2 != string::npos)
        {
            pos = pos_srm2;
        }
        else if (pos_map != string::npos)
        {
            pos = pos_map;
        }
        else
        {
            std::cout << "the message is not SRM/BSM/MAP" << std::endl;
        }

        // END of 20240628 edition 


        
        currentTime = static_cast<double>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

        if (pos != string::npos)
        {
            extractedPayload = receivedPayload.erase(0, pos);
            msgType = decoder.getMessageType(extractedPayload);

            if (msgType == MsgEnum::DSRCmsgID_map)
            {
                if ((applicationPlatform == "vehicle") || ((applicationPlatform == "roadside") && (peerDataDecoding == true)))
                {
                    // std::cout << "application platform: " << applicationPlatform << std::endl;
                    // std::cout << "peerDataDecoding" << peerDataDecoding << std::endl;
                    string mapJsonString = decoder.createJsonStingOfMapPayload(extractedPayload);
                    std::cout << "Received mapJsonString is: " << mapJsonString << std::endl;
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(mapReceiverPortNo), mapJsonString);
                    cout << "[" << fixed << showpoint << setprecision(2) << currentTime << "] Decoded MAP" << endl;
                }
            }

            else if (msgType == MsgEnum::DSRCmsgID_bsm)
            {
                string bsmJsonString = decoder.bsmDecoder(extractedPayload);
                std::cout << "Received BSMJSON String: " << bsmJsonString << std::endl;
                decoderSocket.sendData(HMIControllerIP, static_cast<short unsigned int>(vehicleHmiPortNo), bsmJsonString);
                decoderSocket.sendData(messageDistributorIP, static_cast<short unsigned int>(messageDistributorPort), bsmJsonString);
                if(applicationPlatform=="roadside")
                {
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(trajectoryAwarePortNo), bsmJsonString);
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), bsmJsonString);

                }
                else if(applicationPlatform=="vehicle")
                {
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), bsmJsonString);
                }
                cout << "[" << fixed << showpoint << setprecision(2) << currentTime << "] Decoded BSM" << endl;
            }

            else if (msgType == MsgEnum::DSRCmsgID_srm)
            {
                if ((applicationPlatform == "roadside") || ((applicationPlatform == "vehicle") && (peerDataDecoding == true)))
                {                
                    string srmJsonString = decoder.srmDecoder(extractedPayload);
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(srmReceiverPortNo), srmJsonString);
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), srmJsonString);
                    cout << "[" << fixed << showpoint << setprecision(2) << currentTime << "] Decoded SRM" << endl;
                }
            }

            else if (msgType == MsgEnum::DSRCmsgID_spat)
            {
                if ((applicationPlatform == "vehicle") || ((applicationPlatform == "roadside") && (peerDataDecoding == true)))
                {
                    string spatJsonString = decoder.spatDecoder(extractedPayload);
                    std::cout << "Received spatJsonString is: " << spatJsonString << std::endl;
                    decoderSocket.sendData(HMIControllerIP, static_cast<short unsigned int>(vehicleHmiPortNo), spatJsonString);
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), spatJsonString);
                    cout << "[" << fixed << showpoint << setprecision(2) << currentTime << "] Decoded SPAT" << endl;
                    cout << spatJsonString << endl;
                }
            }

            else if (msgType == MsgEnum::DSRCmsgID_ssm)
            {
                if ((applicationPlatform == "vehicle") || ((applicationPlatform == "roadside") && (peerDataDecoding == true)))
                {                
                    string ssmJsonString = decoder.ssmDecoder(extractedPayload);
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(ssmReceiverPortNo), ssmJsonString);
                    decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), ssmJsonString);
                    cout << "[" << fixed << showpoint << setprecision(2) << currentTime << "] Decoded SSM" << endl;
                }
            }
        }

        if (decoder.sendSystemPerformanceDataLog())
        {
            if (applicationPlatform == "roadside")
            {
                decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), decoder.createJsonStringForSystemPerformanceDataLog("RemoteBSM"));
            }

            else if (applicationPlatform == "vehicle")
            {
                decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), decoder.createJsonStringForSystemPerformanceDataLog("RemoteBSM"));
                decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), decoder.createJsonStringForSystemPerformanceDataLog("SSM"));
                decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), decoder.createJsonStringForSystemPerformanceDataLog("MAP"));
                decoderSocket.sendData(LOCALHOST, static_cast<short unsigned int>(dataCollectorPortNo), decoder.createJsonStringForSystemPerformanceDataLog("SPaT"));
            }
        }
    }

    return 0;
}

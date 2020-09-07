#include <string>
#include <sstream>
#include <fstream>
#include "RsuMsgPacket.h"
#include "json/json.h"


RsuMsgPacket::RsuMsgPacket()
{
    Json::Value jsonObject_config;
    Json::Reader reader;
    std::ifstream configJson("/nojournal/bin/mmitss-phase3-master-config.json");
    std::string configJsonString((std::istreambuf_iterator<char>(configJson)), std::istreambuf_iterator<char>());
    reader.parse(configJsonString.c_str(), jsonObject_config);

    bsmMsgId = jsonObject_config["msgId"]["bsm"].asString();
    srmMsgId_lower = jsonObject_config["msgId"]["srm_lower"].asString();
    srmMsgId_upper = jsonObject_config["msgId"]["srm_upper"].asString();
    spatMsgId = jsonObject_config["msgId"]["spat"].asString();
    mapMsgId = jsonObject_config["msgId"]["map"].asString();
    ssmMsgId_lower = jsonObject_config["msgId"]["ssm_lower"].asString();
    ssmMsgId_upper = jsonObject_config["msgId"]["ssm_upper"].asString();

    bsmPsid = jsonObject_config["psid"]["bsm"].asString();
    srmPsid = jsonObject_config["psid"]["srm"].asString();
    spatPsid = jsonObject_config["psid"]["spat"].asString();
    mapPsid = jsonObject_config["psid"]["map"].asString();
    ssmPsid = jsonObject_config["psid"]["ssm"].asString();

    bsmTxChannel = jsonObject_config["TxChannel"]["bsm"].asInt();
    srmTxChannel = jsonObject_config["TxChannel"]["srm"].asInt();
    mapTxChannel = jsonObject_config["TxChannel"]["map"].asInt();
    spatTxChannel = jsonObject_config["TxChannel"]["spat"].asInt();
    ssmTxChannel = jsonObject_config["TxChannel"]["ssm"].asInt();

    bsmTxMode = jsonObject_config["TxMode"]["bsm"].asString();
    srmTxMode = jsonObject_config["TxMode"]["srm"].asString();
    spatTxMode = jsonObject_config["TxMode"]["spat"].asString();
    mapTxMode = jsonObject_config["TxMode"]["map"].asString();
    ssmTxMode = jsonObject_config["TxMode"]["ssm"].asString();


}

void RsuMsgPacket::setMsgType(std::string msgId)
{
    if(msgId == mapMsgId)
        type = "MAP";
    if(msgId == bsmMsgId)
        type = "BSM";
    if(msgId == srmMsgId_lower || msgId == srmMsgId_upper)
        type = "SRM";
    if(msgId == spatMsgId)
        type = "SPAT";
    if(msgId == ssmMsgId_lower || msgId == ssmMsgId_upper)
        type = "SSM";
}

void RsuMsgPacket::setPsid(std::string msgType)
{
    if(msgType == "MAP")
        psid = "0x" + mapPsid;
    if(msgType == "SPAT")
        psid = "0x" + spatPsid;
    if(msgType == "SSM")
        psid = "0x" + ssmPsid;
    if(msgType == "BSM")
        psid ="0x" + bsmPsid;
    if(msgType == "SRM")
        psid = "0x" + srmPsid;
}

void RsuMsgPacket::setTxMode(std::string msgType)
{
    if(msgType == "MAP")
        txMode = mapTxMode;
    if(msgType == "SPAT")
        txMode = spatTxMode;
    if(msgType == "SSM")
        txMode = ssmTxMode;
    if(msgType == "BSM")
        txMode = bsmTxMode;
    if(msgType == "SRM")
        txMode = srmTxMode;
}

void RsuMsgPacket::setTxChannel(std::string msgType)
{
    if(msgType == "MAP")
        txChannel = mapTxChannel;
    if(msgType == "SPAT")
        txChannel = spatTxChannel;
    if(msgType == "SSM")
        txChannel = ssmTxChannel;
    if(msgType == "BSM")
        txChannel = bsmTxChannel;
    if(msgType == "SRM")
        txChannel = srmTxChannel;
}

std::string RsuMsgPacket::getMsgPacket(std::string msgPayload)
{
    payload = msgPayload;
    std::string msgId = msgPayload.substr(0,4);
    setMsgType(msgId);
    setTxMode(type);
    setTxChannel(type);
    setPsid(type);


    std::stringstream ss{};
    ss << "Version=" << version << std::endl;
    ss << "Type=" << type << std::endl;
    ss << "PSID=" << psid << std::endl;
    ss << "Priority=" << priority << std::endl;
    ss << "TxMode=" << txMode << std::endl;
    ss << "TxChannel=" << txChannel << std::endl;
    ss << "TxInterval=" << txInterval << std::endl;
    ss << "DeliveryStart=" << deliveryStart << std::endl;
    ss << "DeliveryStop=" << deliveryStop << std::endl;
    ss << "Signature=" << signature << std::endl;
    ss << "Encryption=" << encryption << std::endl;
    ss << "Payload=" << payload << std::endl;

    std::string msgPacket = ss.str();

    return msgPacket;
}
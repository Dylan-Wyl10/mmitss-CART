#include <iostream>
#include <string.h>
#include <unistd.h>
#include "MmitssUdpSocket.h"

using std::string;
using std::cout;
using std::endl;

MmitssUdpSocket::MmitssUdpSocket(int port)
{
    if((selfName = socket(AF_INET, SOCK_DGRAM, 0))< 0) // If socket creation is unsuccessful, socket() function returns '-1'.
        cout << "Socket creation unsucessful!" << endl;
    else
    {
        memset(&selfIdentifier, 0, sizeof(selfIdentifier));
        selfIdentifier.sin_family = AF_INET;
        selfIdentifier.sin_addr.s_addr = INADDR_ANY;
        selfIdentifier.sin_port = htons(port);
        if ( bind(selfName, (sockaddr *)&selfIdentifier, sizeof(selfIdentifier)) < 0 )
            cout << "Socket binding unsuccessful!" << endl;
    }
}
void MmitssUdpSocket::send_data(int receiverPort, string sendBuffer)
{
    sockaddr_in receiverIdentifier{};
    receiverIdentifier.sin_family = AF_INET;
    receiverIdentifier.sin_addr.s_addr = INADDR_ANY;
    receiverIdentifier.sin_port = htons(receiverPort);
    socklen_t receiverAddrLen = sizeof(receiverIdentifier);
    sendto(selfName, sendBuffer.c_str(), strlen(sendBuffer.c_str()), 0, (sockaddr*)&receiverIdentifier, receiverAddrLen);
}
void MmitssUdpSocket::send_data(string receiverIP, int receiverPort, string sendBuffer)
{
    sockaddr_in receiverIdentifier{};
    receiverIdentifier.sin_family = AF_INET;
    receiverIdentifier.sin_addr.s_addr = inet_addr(receiverIP.c_str());
    receiverIdentifier.sin_port = htons(receiverPort);
    socklen_t receiverAddrLen = sizeof(receiverIdentifier);
    sendto(selfName, sendBuffer.c_str(), strlen(sendBuffer.c_str()), 0, (sockaddr*)&receiverIdentifier, receiverAddrLen);
}
string MmitssUdpSocket::receive_data()
{
    char receiveBuffer[5120] = "";
    sockaddr_in senderIdentifier{};
    socklen_t senderAddrLen = sizeof(senderIdentifier);
    recvfrom(selfName, receiveBuffer, sizeof(receiveBuffer), 0, (sockaddr*)&senderIdentifier, &senderAddrLen);
    senderPort =  ntohs(senderIdentifier.sin_port);
    senderIP = inet_ntoa(senderIdentifier.sin_addr);
    return receiveBuffer;
}
int MmitssUdpSocket::getSenderPort()
{
    return senderPort;
}
string MmitssUdpSocket::getSenderIP()
{
    return senderIP;
}
void MmitssUdpSocket::close_socket()
{
    close(selfName);
}
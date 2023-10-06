#!/usr/bin/env python
"""
Author: Dylan
Date: 09/29/2023
Note: This work is used for :
    1. receive bsm from Commsignia OBU
    2. decode the bsm payload with J2735-2016 decoder
    3*. encode psedo bsm from TCSCAN as J2735 Standard BSM
    4*. forward J2735 BSM to OBU via UDP protocol
"""
###########################################################################

import BSMEncoder
import socket
import time


class UDP:
    def __init__(self, address):
        self.ip, self.port = address

    def send(self, information):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(information, (self.ip, self.port))

    def receive(self):
        addr = (self.ip, self.port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.03)
        sock.bind(addr)
        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                data = None
            return data


class MessageDistributor:
    def __init__(self, address_dic):
        self.address_re = address_dic['obu']
        self.address_prg = address_dic['prg']
        self.address_bsm = address_dic['bsm']

        # establish udp socket for message flow
        self.udp_re = UDP(self.address_re)
        self.udp_prg = UDP(self.address_prg)
        self.udp_bsm = UDP(self.address_bsm)


    def DistributeMsg(self):
        payload = self.udp_re.receive()  # receive payload from radio device
        type = None  # initial msg type
        if payload is not None:
            print("payload is: ", payload)
            payload_str = str(payload).lower()
            if "0014" in payload_str:
                type = 'BSM'
                self.udp_bsm.send(bytes(bsm_tmp, 'utf-8'))
            elif "00138" in payload_str:
                type = "SPaT"
                self.udp_prg.send(bytes(bsm_tmp, 'utf-8'))
            elif "00128" in payload_str:
                type = "MAP"
                self.udp_prg.send(bytes(bsm_tmp, 'utf-8'))

    # def SendMsg(self, type):

def main():
    # Read the config file into a json object:
    configFile = open("/nojournal/bin/mmitss-phase3-master-config.json", 'r')
    config = (json.load(configFile))

    # Close the config file:
    configFile.close()

    # read ip address and ports from configuration files:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mrpIp = config["HostIp"]
    ReceivePort = config["PortNumber"]["MessageDistributor"]
    HostBsmDecoder= config["PortNumber"]["HostBsmDecoder"]
    Msg


        

if __name__ == '__main__':

    address_dict = {"obu":"",
                    "prg":"",
                    "bsm":"",}
    receive_address = ('0.0.0.0', 10002)
    send_address = ('192.168.2.91', 1516)
    # v2m_address = ('10.12.6.206', 10005)  # v2m means the address from vsp device to mmitss.
    print('run')
    while True:
        distribute_Bsm(receive_address, send_address)
        time.sleep(1)







# def distribute_Bsm(r_address, s_address):
#     r_udp, s_udp = UDP(r_address), UDP(s_address)
#     # payload_string = r_udp.receive()
#     payload_string = '5944a9eaa8049726e0db929bba8fcb0b869414100070000000fdfa1fa1007fff80000000000038c00100023ffe500075f6fffec800'
#     payload_string = '0014354a44a9eaa8055f26e0dc2c1bba8e748b9c9414100070000000fdfa1fa1007fff80000000000038c00100013ffff006027efffec800'
#     payload_string = '004e0000000019676dafd91cb337a808778785000a10006b9a837d57dc8e80c74376000000'
#     # bsm_string = '0000000100000000000000010002181C4EC4CC2C2D870000000000112328058F033F038B00000001847B04E6A2'# add testing example here
#     # bsm_string = '00000002000000000000000100010003e438fffcf7c10000000000010000000002440208047400000001851161658e'
#     # bsm_string = '00000002000000000000000100010003e438fffcf7c1000000000001000000000244020804740000000185116277db'

    
#     if payload_string is not None:
#         decodeMsg(payload_string)
# #        print("bsm from vissim is: ", bsm_string)
        
#         # bsm_pkg = encodeBSM(bsm_string)
#         # print("bsm package is:", bsm_pkg)
#         # print("##########################################################")
#         #  print("payload is:", payload)
#         # print("#########################################################")
#         # s_udp.send(bsm_pkg)
        
        
# def decodeMsg(payload):
#     print(payload)
#     payload = bytes.fromhex(payload)
#     bsm_string = bytearray(payload)
#     print(bsm_string)
#     de_result = BSMEncoder.decode(bsm_string)
#     print("decode result is:", de_result)
#     (id, secMark, msgCount, speed, heading, lat, lon, elev, length, width) = de_result
#     print(f'id: {id}\nsecMark: {secMark}\nmsgCount: {msgCount}\nspeed: {speed}\nheading: {heading}\nlat: {lat}\nlon: {lon}\nelev: {elev}\nlength: {length}\nwidth: {width}')
#     print("##########################################")
        

# def encodeBSM(string):
#     #string_hex = string.hex()
    
#     string_hex = string
#     msgCnt = int(string_hex[0: 8], 16) % 128
#     temporaryID = str(int(string_hex[8: 24], 16))
#     secMark = int(int(string_hex[24: 28], 16)/100) # [0 - 599]

#     ##position
#     lat = int(string_hex[28: 36], 16)
#     lon = - (2 ** 32 - int(string_hex[36: 44], 16))
#     elev = int(int(string_hex[44: 52], 16) / 100)  # what is the unit in Sean's case, current follow MMITSS encoding
#     ## accuracy:
#     semiMajor = 15
#     semiMinor = 10
#     orientation = 20
#     speed = int(int(string_hex[52: 56], 16) / 2)
#     heading = int(int(string_hex[56: 60], 16) / 1.25)
#     angle = 5  # based on Sean's example
#     ## accelerations:
#     acc_long = 5
#     acc_lat = 12
#     acc_vert = 15
#     acc_yaw = 200
#     ## size
#     length = int(int(string_hex[60: 64], 16)/100)  # length unit = dm
#     width = int(int(string_hex[64: 68], 16)/100)   # length unit = dm
#     height = int(int(string_hex[68: 72], 16)/100)  # length unit = dm
    
#     ## epoch time:
#     epoch_time = string_hex[74: 90]
    
#     # print(temp, type(temp))
    
#     #$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
#     # Note: elevation is replaced as height for now!!!!!!!!!!!!!!!!!
#     elev = height
#     #$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
    
#     print(msgCnt,temporaryID, lon, lat, elev, semiMajor, semiMinor, orientation, speed, heading, angle, acc_long, acc_lat, acc_vert, acc_yaw, length, width, msgCnt, secMark, epoch_time)
    
#     x = BSMEncoder.encode(temporaryID, lon, lat, elev, semiMajor, semiMinor, orientation, speed, heading, angle, acc_long, acc_lat, acc_vert, acc_yaw, length, width, msgCnt, secMark)
#     # print(x)
#     x = str(epoch_time) + '001425' + x.hex()
#     bsm_tmp = "Version=0.7\n" + \
#               "Type=BSM\n" + \
#               "PSID=0x20\n" + \
#               "Priority=7\n" + \
#               "TxMode=ALT\n" + \
#               "TxChannel=SCH\n" + \
#               "TxInterval=0\n" + \
#               "DeliveryStart=\n" + \
#               "DeliveryStop=\n" + \
#               "Signature=False\n" + \
#               "Encryption=False\n" + \
#               "Payload=" + x

#     bsm = bytes(bsm_tmp, 'utf-8')
    
#     # x = bytes(x, 'utf-8')
#     print(bsm)

#     # (id, secMark, msgCount, speed, heading, lat, lon, elev, length, width) = BSMEncoder.decode(x)
#     # print(f'id: {id}\nsecMark: {secMark}\nmsgCount: {msgCount}\nspeed: {speed}\nheading: {heading}\nlat: {lat}\nlon: {lon}\nelev: {elev}\nlength: {length}\nwidth: {width}')
#     # print('#######################################################################')

#     return bsm


# if __name__ == '__main__':
#     receive_address = ('0.0.0.0', 10002)
#     send_address = ('192.168.2.91', 1516)
#     # v2m_address = ('10.12.6.206', 10005)  # v2m means the address from vsp device to mmitss.
#     print('run')
#     while True:
#         distribute_Bsm(receive_address, send_address)
#         time.sleep(1)


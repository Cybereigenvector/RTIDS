# -----------------------------------------------------------------------------------
# This module of the IDS is designed to unpack the Ethernet header of the incoming
# network packets
# Created by Rishabh Das program based on Bucky robert's (new boston) network sniffer
# Date 11th July 2018
# -----------------------------------------------------------------------------------
import socket
import struct
from general import *

# This class is invoked from the main sniffer program to unpack the ethernet header portion of the network packet
class Ethernet:

    def __init__(self, raw_data):
        # 6s Siginifies that the Mac address is 6 characters long and the H is
        # for the single unsigned integer for the protocol. Only first 14 bytes
        # are considered for unpacking
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        # Storing the unpacked addresses and the packet header details in the variables
        # This will be accessed from the main sniffer program
        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]




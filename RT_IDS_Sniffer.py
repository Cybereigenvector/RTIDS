# ----------------------------------------------------------------
# This is the sniffer module of the IPS. All incoming packets into
# the IPS is sniffed by this module and a database having all
# information about the incoming packets are compiled into that
# database. The Data that is saved on to the data base is also
# parsed and interpreted by this module
# -> Sniffs the traffic from the designated interface
# -> Compiles the data base and makes it accessible to the machine
# learning program
#
# Future Plans:-
# -> The program needs to generic so that new protocols can be incorporated
#  into the program whenever necessary
# -> This program needs to communicate with the web interface so that
#   features can be selected
#
# Dependencies:-
# -> pyshark
# By:- Rishabh Das
# ----------------------------------------------------------------
import socket
from ethernet import *
from RT_General import *
import subprocess as sub

class Sniffer:

    # ------------------------------------------------------------
    # Initializes the variables that would be used through out the
    # program. This is the constructor
    # ------------------------------------------------------------

    def __init__(self, prt=502):
        self.port = prt
        print ("Expecting traffic in port " + str(prt))

    def trial_func(self):
        p = sub.Popen(('sudo', 'tcpdump', 'port','502','-XX'), stdout=sub.PIPE)
        count = 0
        temp_string = ""
        for row in iter(p.stdout.readline, b''):
            count = count + 1
            temp_string = temp_string + str(row.rstrip())
            print (temp_string)


    def parse_fields(self):
        print("Try")

    # ------------------------------------------------------------
    # This function connects the sniffer to the network port. The
    # sniffer starts monitoring the packet coming into the
    # network port.
    # ------------------------------------------------------------

    def connect_adapter(self):
        connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while(True):
            raw_data, addr = connect.recvfrom(self.port)
            eth = Ethernet(raw_data)
            print('Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))
            #print("This Function is trying to connect to " + self.port + "\nThe extracted data is :" + eth.dest_mac )


    def get_info(self):
        # Getting information about the ethernet header
        dest
        print("Get the infor from the network packets coming in")
    def store_info_to_DB(self):
        print("Storing the received info into a database")
    def print_info(self):
        print("Printing the received packets in parsed format")
    def sniffer_handler(self):
        print("This function handles all the function when it is called from an external program")

snif = Sniffer(502)
#snif.trial_func()
snif.connect_adapter()


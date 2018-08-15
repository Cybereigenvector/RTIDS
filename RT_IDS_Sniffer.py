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


class Sniffer:


    def connect_adapter(self,prt = 502):
        connect = socket.socket(socket.AF_PACKET, socket_SOCK_RAW, scoket.ntohs(3))
        raw_data, addr = connect.recvfrom(prt)

        print("This Function connects the ")


    def get_info(self):
        print("Get the infor from the network packets coming in")
    def store_info_to_DB(self):
        print("Storing the received info into a database")
    def print_info(self):
        print("Printing the received packets in parsed format")
    def sniffer_handler(self):
        print("This function handles all the function when it is called from an external program")


# ----------------------------------------------------------------
# This is the server module of the IPS that replies to any client
# that tries to connect to the server. Specific commands are
# supported by the server. These commands replies the clients with
# specific information about the IPS
# -> Receives the messages from the clients
# -> Replies with the status of the IPS
#
# Future Plans:-
# -> Find the configuration of the IPS
# -> A number of custom messages and commands will be interpreted
#    with the IPS
#
# Dependencies:-
# ->
# By:- Rishabh Das
# ----------------------------------------------------------------

import socket
import threading

class IPSserver:

    # ------------------------------------------------------------
    # Initializes the variables that would be used through out the
    # program. This is the constructor
    # ------------------------------------------------------------

    def __init__(self,prt=5001,addr='127.0.0.1'):
        self.port=prt
        self.ip=addr

    # ------------------------------------------------------------
    # This function creates the server. The server starts listening
    # on the defined  port and the IP once the create server
    # function is invoked by the calling program
    # ------------------------------------------------------------

    def create_server(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("Socket created successfully!")

        except socket.error as err:
            print("Socket creation error!!")
        
        try:
            sock.bind((self.ip, self.port))
            sock.listen(1)

        except socket.error as err:



    def start_server(self):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("Socket successfully created!")
        except socket.error as err:
            print("Socket creation error!!")


    def stopserver(self):



try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
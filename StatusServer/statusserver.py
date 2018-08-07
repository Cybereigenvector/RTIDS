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
import sys
import threading

class IPSserver:

    # ------------------------------------------------------------
    # Initializes the variables that would be used through out the
    # program. This is the constructor
    # ------------------------------------------------------------

    def __init__(self,prt=5001,addr='127.0.0.1'):
        self.port=prt
        self.ip=addr
        self.connections = []
    # ------------------------------------------------------------
    # This function creates the server. The server starts listening
    # on the defined  port and the IP once the create server
    # function is invoked by the calling program
    # ------------------------------------------------------------

    def initialize_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print("Socket created successfully!")

        except socket.error as err:
            print("Socket creation error!!")
            sys.exit()

        try:
            self.sock.bind((self.ip, self.port))
            print("Socket binded successfully!")

        except socket.error as err:
            print("Socket failed to bind!!")
            sys.exit()

        self.sock.listen(10)
        print("Server initialization successful!")

    # -----------------------------------------------------------
    # This handler function is executed by the thread assigned to
    # client. This function receives data and the calls the
    # necessary functions. This function also sends appropriate
    # reply to the
    # -----------------------------------------------------------

    def client_handler(self,client,client_addr):
        print(client_addr)
        while True:
            data = client.recv(1024)
            print(data.strip())
            reply = self.interprete_data(data.strip())
            client.sendto(reply,client_addr)
            if not data:
                break
            print(threading.currentThread().getName() +": "+ data)

    # -----------------------------------------------------------
    # This function interprets the received commands and calls the
    # necessary function to perform the required operations.
    # -----------------------------------------------------------

    def interprete_data(self,msg):
        prepstr=""
        if msg == "Hi":
            prepstr ="Hi_returned"
        elif msg == "Hello":
            prepstr ="Hello_returned"
        else:
            prepstr ="Something else!!"
        return prepstr

    # -----------------------------------------------------------
    # This function receives the clients and assigns a handler to
    # the clients.
    # -----------------------------------------------------------

    def start_server(self):
        i=0
        print("Listening on " + str(self.ip) + " port " + str(self.port))
        while True:
            client, client_addr = self.sock.accept()
            i=i+1
            clientthread = threading.Thread(target=self.client_handler,args=(client, client_addr),name="Client " + str(i))
            clientthread.daemon = True
            clientthread.start()
            self.connections.append(client)
            print(self.connections)


ins= IPSserver(5002,"192.168.137.205")
ins.initialize_server()
ins.start_server()
#ins.client_handler()

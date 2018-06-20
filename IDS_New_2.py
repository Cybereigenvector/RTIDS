# ------------------------------------------------------------------------------------------
# This is a core RT IDS code. This Code starts a relay server on the Rasberry pi and
# listens on the the port 502 instead of the openplc. Finally the received packets are
# relayed back to the openplc. The packets being send to the openplc is monitored by the
# machine learning algorithm. Finally if an attack is detected by the algorithm the packet
# is dropped and the trusted node is added to a blacklist. This IDS provides protection
# against the following attack vectors
#
# Algorithms used:-
# 1.K-means
#
#
# Attack Vectors Detected:-
# 1.DOS(Volumetric DOS)
# 2.Network anomaly
#
# @Rishabh Das
# @Proxy Server code based on Ricardo Pascal's relay server code
# Date:-2nd November 2017
# ------------------------------------------------------------------------------------------
from __future__ import print_function
import socket
import select
from datetime import datetime
import time
import sys
import signal
import os

# machine Learning and Data manipulation libraries
import numpy as np
from sklearn.cluster import KMeans
from scipy.spatial.distance import cdist

# Threading libraries
import threading
import logging

# ------------------------------------------------------------------------------------------
# Declaring the buffer size of the packets and the network delay. The forward details of
# the OpenPLC port is also declared. Changing the forward to details would determine the
# port the RT_IDS will connect to on the PLC Side
# ------------------------------------------------------------------------------------------
buffer_size = 4096
delay = 0.0009
forward_to = ('localhost', 4321)  # Change This!!!


def die_gracefully(signum, frame):
    server.server_close()
    sys.exit(0)


class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print(e)
            return False


# -------------------------------------------------------------------------------------------
# The Server class. The machine learning algorithm is embedded in the server class
# -------------------------------------------------------------------------------------------
class TheServer:
    input_list = []
    channel = {}

    # The realtime dataset created by the system is stored in this  python list
    # later this python list is converted to a numpy array
    dataset = []

    # Packet timing
    prev = datetime.now()
    current = datetime.now()

    # attack detected and fallback control
    flag = 0

    # count of suspicious packets
    count = 0

    # count incoming packets
    cnt = 0

    # locks for training and reset
    final = 0
    trained = 0
    lock = 0
    alive = 0

    # algorithm
    kmeans = KMeans(n_clusters=1, random_state=0)
    cluster_center = []

    # Record of connected clients and servers in the system
    white_list = []
    new_connections = []

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('', port))
        self.server.listen(2)

    def server_close(self):
        self.server.close()

    def main_loop(self):
        #self.restore_initial_state()
        self.input_list.append(self.server)
        self.flag = 0
        self.count = 0
        while self.flag == 0:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                self.cnt = self.cnt + 1
                self.current = datetime.now()
                if self.s == self.server:
                    self.on_accept()
                    break
                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()
                x = (self.current - self.prev).microseconds
                self.prev = self.current

                if len(self.dataset) < 20 and self.trained == 0 and self.cnt > 100:
                    if self.s.getpeername()[0] not in self.white_list:
                        self.white_list.append(self.s.getpeername()[0])
                    if self.s.getpeername()[0] == '127.0.0.1' and self.trained == 0:
                        self.dataset.append(x)
                        print("Collecting Data...")
                        sys.stdout.flush()
                        #print(x, self.s.getpeername()[0])
                        #print("Whitelist->", self.white_list)
                elif self.lock == 0 and self.cnt >100:
                    print("Data is ready for training")
                    sys.stdout.flush()
                    Algorithm_trainer = threading.Thread(target=self.train)
                    self.lock = 1
                    self.trained = 0
                    Algorithm_trainer.start()
                if self.trained == 1:
                    if len(self.dataset) < 20 and self.final != 2:
                        if self.s.getpeername()[0] == '127.0.0.1':
                            self.dataset.append(x)
                            #print(len(self.dataset))
                    elif self.final == 1 and self.lock == 1:
                        self.lock = 0
                    if (self.s.getpeername()[0] not in self.white_list and self.s.getpeername()[
                        0] not in self.new_connections):
                        self.new_connections.append(self.s.getpeername()[0])
                    if self.s.getpeername()[0] == '127.0.0.1' and x < (self.cluster_center - 200) and self.final == 2:
                        self.count = self.count + 1
                        if self.alive == 0:
                            print("Count Reset Started")
                            sys.stdout.flush()
                            count_reset_handler = threading.Thread(target=self.count_reset)
                            count_reset_handler.start()
                            self.alive = 1
                        #print(x)
                        if self.count == 10:
                            if len(self.new_connections) != 0:
                                print(
                                    "Possible DOS attack!!\nNOTE:-The server was stopped to protect the PLC from DOS attack\nService would be restarted after 5 sec")
                                sys.stdout.flush()
                                print("Supected IP has been blacklisted", self.new_connections)
                                sys.stdout.flush()
                                st = 'sudo iptables -A INPUT -s ' + self.new_connections[0] + ' -j DROP'
                                os.system(st)
                                self.flag = 1
                                self.write_log()
                                self.write_RT_IDS_Cluster()
                                time.sleep(1)
                            else:
                                print("Possible network anomaly detected!!\nLow network latency!!!")
                                sys.stdout.flush()
                                time.sleep(1)


    # -------------------------------------------------------------------------------------------
    # This function writes the starting cluster center to a file after an attack has been detected
    # -------------------------------------------------------------------------------------------
    def write_RT_IDS_Cluster(self):
        print ("Writing Cluster Info")
        sys.stdout.flush()
        # Write the cluster centers in a file
        RT_IDS_Config = open("RT_IDS_Config.txt","w")
        sys.stdout.flush()
        print(self.cluster_center, file=RT_IDS_Config)
        RT_IDS_Config.close()

    # -------------------------------------------------------------------------------------------
    # This function restores the state of the program once the IDS has recovered from a DOS attack
    # -------------------------------------------------------------------------------------------
    def restore_initial_state(self):
        # Not an active feature
        if os.path.exists("RT_IDS_Log.txt"):
            print("IDS Restoring state......")
            reader = open("RT_IDS_Log.txt","r")
            last_line=''
            for line in reader:
                last_line=line
            reader.close()
            word=last_line.split()
            last_attack=datetime.strptime(word[len(word)-2]+" "+word[len(word)-1],"%Y-%m-%d %H:%M:%S.%f")
            present_time=datetime.strptime(datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),"%Y-%m-%d %H:%M:%S.%f")
            if((present_time-last_attack).seconds >120):
                print ("IDS will be trained!")
                '''
            else:
                if os.path.exists("RT_IDS_Config.txt"):
                    reader = open("RT_IDS_Config.txt", "r")
                    line=reader.readline()
                    line=line[2:len(line)-3]
                    reader.close()
                    self.cluster_center=float(line)
                    self.flag=2
                    self.trained=1
                    self.lock=1
                    print("State successfully restored")
                else:
                    print("IDS will be trained!")'''
        else:
            print ("IDS running for the first time")
    # -------------------------------------------------------------------------------------------
    # This function writes the information about the detected attack to a file
    # -------------------------------------------------------------------------------------------
    def write_log(self):
        msg=""
        print("Writing Attack history")
        # Write the cluster centers in a file
        RT_IDS_Log = open("RT_IDS_Log.txt", "a")
        for ip_att in self.new_connections:
            msg="Possible DOS attack from IP "+ip_att+" "+datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            print(msg, file=RT_IDS_Log)
            msg=""
        RT_IDS_Log.close()

    # -------------------------------------------------------------------------------------------
    # This function is executed by a thread
    # -------------------------------------------------------------------------------------------
    def count_reset(self):
        time.sleep(5)
        self.count = 0
        self.alive = 0
        self.cluster_center= self.cluster_center-15
        print("Count Reset successful !")
        sys.stdout.flush()

    # -------------------------------------------------------------------------------------------
    # This function handles the cases when a connection is opened with a client
    # -------------------------------------------------------------------------------------------
    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        # self.current_connections_addr.append(clientaddr)
        if forward:
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print("Can't establish connection with remote server.")
            sys.stdout.flush()
            print("Closing connection with client side", clientaddr)
            sys.stdout.flush()
            clientsock.close()

    # ------------------------------------------------------------------------------------------
    # This function handles the cases when a connection is closed with a client
    # ------------------------------------------------------------------------------------------
    def on_close(self):
        print(self.s.getpeername(), "has disconnected")
        sys.stdout.flush()
        # remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    # -----------------------------------------------------------------------------------------
    # This function trains the machine learning algorithm once the dataset is ready
    # -----------------------------------------------------------------------------------------
    def train(self):
        print("Data is being processed")
        sys.stdout.flush()
        raw_data = np.array(self.dataset)
        mean = np.mean(raw_data)
        newdata = []
        #print("The mean is->", mean)
        for num in raw_data:
            if num < mean * 2:
                newdata.append(num)
        #print(newdata)
        print("The IDS algorithm is being trained")
        sys.stdout.flush()
        self.kmeans.fit_predict(np.array(newdata).reshape(-1, 1))
        # Verify the performance using coefficient
        self.cluster_center = self.kmeans.cluster_centers_
        #print(self.cluster_center)
        del self.dataset[:]
        self.final = self.final + 1
        if self.final == 2:
            ##setting final training flag after this step the algorithm is fully functional
            print("RT_IDS Started Monitoring!!")
            sys.stdout.flush()
        else:
            print("RT_IDS Started calibrating!!")
            sys.stdout.flush()
        self.trained = 1

    # ------------------------------------------------------------------------------------------
    # The dataset is prepared realtime in this framework and once ready the dataset is used for
    # training the algorithm.The training is performed by a separate thread
    # ------------------------------------------------------------------------------------------
    def on_recv(self):
        data = self.data
        self.channel[self.s].send(data)

# ---------------------------------------------------------------------------------------
# This is the main function. This function calls the the server and the
# necessary functions
# ---------------------------------------------------------------------------------------
if __name__ == '__main__':
    server = TheServer('localhost', 502)
    signal.signal(signal.SIGINT, die_gracefully)
    signal.signal(signal.SIGTERM, die_gracefully)
    try:
        while 1:
            server.main_loop()
            sys.exit(1)
    except KeyboardInterrupt:
        print("Ctrl C - Stopping server")
        sys.stdout.flush()
        sys.exit(1)

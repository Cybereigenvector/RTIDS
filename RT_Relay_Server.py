#------------------------------------------------------------------------------------------
#This is a core RT IDS code. This Code starts a relay server on the Rasberry pi and 
#listens on the the port 502 instead of the openplc. Finally the received packets are 
#relayed back to the openplc. The packets being send to the openplc is monitored by the 
#machine learning algorithm. Finally if an acctak is detected by the algorithm the packet 
#is dropped anf the trusted node is added to a blacklist. This IDS provides protection 
#against the following attack vectors
#
#Algorithms used:- 
#1.K-means
#
#
#Attack Vectors Detected:-
#1.DOS(Volumetric DOS)
#2.Network anomaly
#
#@Rishabh Das
#Date:-2nd November 2017 
#------------------------------------------------------------------------------------------
import socket
import select
from datetime import datetime
import time 
import sys
import signal
import os

#machine Learning and Data manipulation libraries
import numpy as np
from sklearn.cluster import KMeans
from scipy.spatial.distance import cdist

#Threading libraries
import threading
import logging


#------------------------------------------------------------------------------------------
#Declaring the buffer size of the packets and the network delay. The forward details of 
#the OpenPLC port is also declared. Changing the forward to details would determine the 
#port the RT_IDS will connect to on the PLC Side 
#------------------------------------------------------------------------------------------
buffer_size = 4096
delay = 0.0001
forward_to = ('localhost', 4321)#Change This!!!

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
            print (e)
            return False
#-------------------------------------------------------------------------------------------
#The Server class. The machine learning algorithm is embedded in the server class 
#-------------------------------------------------------------------------------------------
class TheServer:
    input_list = []
    channel = {}
    dataset = []
    prev=datetime.now()
    current=datetime.now()
    flag=0
    count=0
    trained=0
    lock=0
    kmeans=KMeans(n_clusters=2, random_state=0)
    min_dist=[0]
    white_list=[]
    black_list=[]
    current_connections_addr=[]

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('', port))
        self.server.listen(2)

    def server_close(self):
        self.server.close()

    def main_loop(self):
        self.input_list.append(self.server)
        self.flag=0
        self.count=0
        while (self.flag==0):
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss (self.input_list, [], [])
            for self.s in inputready:
                self.current=datetime.now()
                if self.s == self.server:
                    self.on_accept()
                    break
                #print(self.channel)
                self.data = self.s.recv(buffer_size)
                #print(self.s.getpeername())
                if len(self.data) == 0:# or self.s.getpeername() != '192.168.137.1':
                    self.on_close()
                    break
                else:
                    self.on_recv()
                #list_l=self.s.getpeername()
                #print(list_l)
                if(self.s.getpeername()!='127.0.0.1' and self.trained == 0):
                    if (self.s.getpeername() not in self.white_list):
                        self.white_list.append(self.s.getpeername())
                    x=(self.current-self.prev).microseconds
                    print((x),self.s.getpeername())
                    print("Whitelist->",self.white_list)
                    self.prev=self.current

    def on_accept(self):   
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        #self.current_connections_addr.append(clientaddr)
        if forward:
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock          
        else:
            print ("Can't establish connection with remote server.")
            print ("Closing connection with client side", clientaddr)
            clientsock.close()            

    def on_close(self):
        print (self.s.getpeername(), "has disconnected")
        #remove objects from input_list
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

#-----------------------------------------------------------------------------------------
#This function trains the machine learning algorithm once the dataset is ready
#-----------------------------------------------------------------------------------------
    def train(self):
        print("The IDS algorithm is being trained")
        #print (self.dataset)
        y=np.array(self.dataset)
        z=y.reshape(-1,1)
        self.kmeans.fit_predict(z)
        print(self.kmeans.cluster_centers_)
        self.trained=1
        print("RT_IDS Started Monitoring!!")

#------------------------------------------------------------------------------------------
#The dataset is prepared realtime in this framework and once ready the dataset is used for 
#training the algorithm.The training is performed by a separate thread 
#------------------------------------------------------------------------------------------
    def on_recv(self):
        data = self.data
        '''
        self.current=datetime.now()
        x=(self.current-self.prev).microseconds
        if (x>0 and x<10000): 
            print(x)   
            if(len(self.dataset)<200):
                print(x,self.s.getpeername())
                self.dataset.append(x)
            elif(self.lock==-1):
                print("Data is ready for training")
                thread1 = threading.Thread(target=self.train)
                self.lock=1
                thread1.start()
            if(x<200):# and x<5000 and x<clus_min*2):
                print(self.min_dist)
                #print(x)
                self.count=self.count+1
                if(self.count==7):
                    self.flag=1
                    print("Possible DOS attack!!\nNOTE:-The server was stopped to protect the PLC from DOS attack\nService would be restarted after 5 sec")
                    print("Supected node ",self.s.getpeername())
                    #print("Suspected attack from ",self.current_connections_addr[0])
                    #self.blacklist.append(self.current_connections_addr[0])                    
            if(self.trained==10):
                before=datetime.now()
                self.min_dist = np.min(cdist([[x]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
                clus_min=np.amin(self.kmeans.cluster_centers_)
                after=datetime.now()
                print(self.min_dist)
                #print(x)
                #print((after-before).microseconds)
                #print("\n\n")
                if(self.min_dist<1500):# and x<5000 and x<clus_min*2):
                    print(self.min_dist)
                    #print(x)
                    self.count=self.count+1
                    if(self.count==7):
                        self.flag=1
                        #self.server.close()
                        #self.server.shutdown(socket.SHUT_RDWR)
        self.prev=self.current'''
        self.channel[self.s].send(data)

#---------------------------------------------------------------------------------------
#This is the main function. This function calls the the server and the 
#necessary functions 
#---------------------------------------------------------------------------------------
if __name__ == '__main__':
        server = TheServer('localhost', 502) #Change This!!!!
        signal.signal(signal.SIGINT, die_gracefully)
        signal.signal(signal.SIGTERM, die_gracefully)
        try:
            while 1:
                server.main_loop()
                #print("Possible DOS attack!!\nNOTE:-The server was stopped to protect the PLC from DOS attack\nService would be restarted after 5 sec")
                time.sleep(5)
                #server.server_close()
        except KeyboardInterrupt :
            print ("Ctrl C - Stopping server")
            sys.exit(1)
###########################################################################################
#This is a core RT IDS code which Creates a relay server to 
#
#
###########################################################################################
import socket
import select
from datetime import datetime
import time 
import sys

#machine Learning and Data manipulation libraries
import numpy as np
#from sklearn.neighbors import LocalOutlierFactor
#from sklearn.neighbors import NearestNeighbors
from sklearn.cluster import KMeans

from scipy.spatial.distance import cdist

#Threading libraries
import threading
import logging

buffer_size = 4096
delay = 0.0001
forward_to = ('localhost', 4321)#Change This!!!

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
    #clf= LocalOutlierFactor(n_neighbors=20)
    #clf2=NearestNeighbors(radius=200)
    kmeans=KMeans(n_clusters=2, random_state=0)
    min_dist=[0]

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(2)

    def main_loop(self):
        self.input_list.append(self.server)
        self.flag=0
        self.count=0
        while (self.flag==0):
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):     
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        if forward:
            print (clientaddr, "has connected")
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

    def train(self):
        print("The IDS algorithm is being trained")
        #print (self.dataset)
        y=np.array(self.dataset)
        z=y.reshape(-1,1)
        self.kmeans.fit_predict(z)
        print(self.kmeans.cluster_centers_)
        self.min_dist = np.min(cdist([[1500]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
        print(self.min_dist)
        self.min_dist = np.min(cdist([[50000]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
        print(self.min_dist)
        self.min_dist = np.min(cdist([[100]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
        print(self.min_dist)
        self.min_dist = np.min(cdist([[500]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
        print(self.min_dist)
        self.min_dist = np.min(cdist([[900]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
        print(self.min_dist)
        self.min_dist = np.min(cdist([[2200]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
        print(self.min_dist)
        #np.reshape(y,-1)
        #self.clf2.fit(y.reshape(-1,1))
        #print(self.clf2)
        #lis_t=self.clf2.kneighbors(100)
        #print(lis_t[2])
        #print(trained_classifier.fit_predict(1000))
        self.trained=1
        time.sleep(5)
        #print(y.reshape(-1,1))
        print("RT_IDS Started Monitoring!!")
        
        #The algorithm would be trained here

    def on_recv(self):
        data = self.data
        self.current=datetime.now()
        x=(self.current-self.prev).microseconds
        if (x>0):    
            #print(x)
            if(len(self.dataset)<200):
                print(len(self.dataset))
                self.dataset.append(x)
                #np.append(self.dataset,x,axis=None)
            elif(self.lock==0):
                print("Data is ready for training")
                thread1 = threading.Thread(target=self.train)
                self.lock=1
                thread1.start()
            if(self.trained==1):
                self.min_dist = np.min(cdist([[x]], self.kmeans.cluster_centers_, 'euclidean'), axis=1)
                if(self.min_dist>1000 and x<5000 and x<np.amin(self.kmeans.cluster_centers_)):
                    print(self.min_dist)
                    print(x)
                    self.count=self.count+1
                    if(self.count==7):
                        self.flag=1
                        #self.server.close()
                        #self.server.shutdown(socket.SHUT_RDWR)
        self.prev=self.current
        #if ((self.current-self.prev).microseconds>0):
        	#print((self.current-self.prev).microseconds)
        # here we can parse and/or modify the data before send forward
        #print (data)
        self.channel[self.s].send(data)



if __name__ == '__main__':
        server = TheServer('192.168.137.113', 502) #Change This!!!!
        try:
            while 1:
                server.main_loop()
                print("Possible DOS attack!!\nNOTE:-The server was stopped to protect the PLC from DOS attack\nService would be restarted after 5 sec")
                time.sleep(5)
        except KeyboardInterrupt:
            print ("Ctrl C - Stopping server")
            sys.exit(1)
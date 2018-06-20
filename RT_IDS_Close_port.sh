#!/bin/bash
#This program sets the IPtable rules to block the port 4321 from the external network
#this port is made available only to the IPS for localhost communication
# 
#@Rishabh Das
#5th November 2017
#-------------------------------------------------------------------
iptables -A INPUT -p tcp -s localhost --dport 4321 -j ACCEPT
iptables -A INPUT -p tcp --dport 4321 -j DROP


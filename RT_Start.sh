#!/bin/bash
#This script monitors if the RT_IDS is alive or not. If the 
#IDS is killed by an attack the IDS is restarted by the script
#@Rishabh Das
#@Date- 2nd November 2017
#--------------------------------------------------------------
while :
do
    echo 'Starting IDS.......'
    sudo python RT_Relay_Server.py 
    sleep 5
done

echo 'Starting IDS.......'
sleep 1
sudo python RT_Relay_Server.py 
if pidof -s RT_Relay_Server.py > /dev/null; then
    echo 'It is already running!'
else
    echo 'process not found...'
fi

while :
do
  sleep 1
  if [[ $(pgrep RT_Relay_Server.py) ]]; then
    sleep 10
  else
    sleep 1
    echo 'Starting IDS.......'
    sudo python RT_Relay_Server.py &
    sleep 5
  fi
done




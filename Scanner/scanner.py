#----------------------------------------------------------------
# This module scans the network of the IDS to detect
# other instances of IDS running on the network. This
# scanning module also creates a list of active clients.
# By:- Rishabh Das
#----------------------------------------------------------------

import nmap


class scanner

    #----------------------------------------------------------------------------
    # Init function that initializes the functions and the variables when the
    # scanner is called from its instance
    #----------------------------------------------------------------------------
    def __init__(self,range,port):
        iprange_range = range                   # Provides the Ip addresses of the network to be scanned
        port_range = port                       # provides a list of ports to be scanned, if the list is
                                                # empty all ports are scanned
    #----------------------------------------------------------------------------
    #   This module is the actual scanner that scans the network to find the
    #   potential PLCs and the instances of the IDS running
    #-----------------------------------------------------------------------------
    def scan(self):
        network_scanner=nmap.PortScanner()
        network_scanner.scan(192)
    #-----------------------------------------------------------------------------
    #   Compiles a list of Online IPS or the PLCs
    #-----------------------------------------------------------------------------
    def create_list(self):

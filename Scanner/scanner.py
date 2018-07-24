#----------------------------------------------------------------
# This module scans the network of the IDS to detect
# other instances of IDS running on the network. This
# scanning module also creates a list of active clients.
# By:- Rishabh Das
#----------------------------------------------------------------

import nmap
import netifaces

class scanner:

    #----------------------------------------------------------------------------
    # Init function that initializes the functions and the variables when the
    # scanner is called from its instance
    #----------------------------------------------------------------------------
    def __init__(self,range,port):
        self.ip_range = range                   # Provides the Ip addresses of the network to be scanned
        self.port_range = port                       # provides a list of ports to be scanned, if the list is
                                                # empty all ports are scanned
    #----------------------------------------------------------------------------
    #   This module is the actual scanner that scans the network to find the
    #   potential PLCs and the instances of the IDS running
    #-----------------------------------------------------------------------------
    def scan_fun(self):
        network_scanner=nmap.PortScanner()
        network_scanner.scan('192.168.137.205','10-443')
        print(network_scanner.all_hosts())
        print(network_scanner.scaninfo())
    #-----------------------------------------------------------------------------
    #   Compiles a list of Online IPS or the PLCs
    #-----------------------------------------------------------------------------
   # def create_list(self):

    #-----------------------------------------------------------------------------
    # Scans for network interfaces that is active on the computer
    #-----------------------------------------------------------------------------
    def is_interface_up(interface):
        addr = netifaces.ifaddresses(interface)
        return netifaces.AF_INET in addr

#nm=scanner(123,123)
#nm.scan

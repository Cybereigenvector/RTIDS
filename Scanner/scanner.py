# ----------------------------------------------------------------
# This module scans the network of the IDS to detect
# other instances of IDS running on the network. This
# scanning module also creates a list of active clients.
# By:- Rishabh Das
# ----------------------------------------------------------------
import netifaces

class NetworkScanner:

    # ----------------------------------------------------------------------------
    # Init function that initializes the functions and the variables when the
    # scanner is called from its instance
    # ----------------------------------------------------------------------------

    def __init__(self):
        self.mac_list = []
        self.ip_list = []
        self.interface_list = []

    # --------------------------------------------------------------------------------
    # This functions finds all the interfaces. The Associated IP addresses and the
    # MAC addresses with that interfaces and compiles a dictionary
    #
    # These numbers are for troubleshooting, in reality AF_LINK or AF_INET would be used
    # directly to access the information. These number migh be system dependent
    # 17-> AF_LINK - This is the link layer interface and the MAC Address is recorded
    #      from this interface
    # 2 -> AF_INET - This is the normal internet interface and the IP address is
    #      recorded from this interface
    # 10-> IPv6 - This is not considered in this IPS code. The IPS can only handle
    # --------------------------------------------------------------------------------

    def interfaces(self):
        self.interface_list = netifaces.interfaces()
        print(self.interface_list)
        for i in self.interface_list:
            addrs = netifaces.ifaddresses(i)
            link = netifaces.AF_LINK
            internet = netifaces.AF_INET
            bool_internet = False
            bool_mac =False
            for k, v in addrs.items():
                if k is link:
                    bool_mac = True
                    for x in v:
                        self.mac_list.append(x['addr'])
                elif k is internet:
                    bool_internet = True
                    for x in v:
                        self.ip_list.append(x['addr'])
            if not bool_internet:
                self.ip_list.append("NA")
            if not bool_mac:
                self.mac_list.append("NA")
        print(self.ip_list)
        print(self.mac_list)

    # ------------------------------------------------------------------------------
    # This function creates record of the Mac addresses and the IP adresses
    # ------------------------------------------------------------------------------

    def create_record(self):
        if self.mac_list == [] or self.ip_list== []:
            print ("The lists are empty !! \nNothing to Write")
        else:
            print("Writing to file!!!")
    # ------------------------------------------------------------------------------
    # The IP addresses and the MAC Addresses are formatted by this function
    # ------------------------------------------------------------------------------

    def format_addr(self):
        # This function formats the addresses found in the list
        print("Hello World")
    # ----------------------------------------------------------------------------
    #   This module is the actual scanner that scans the network to find the
    #   potential PLCs and the instances of the IDS running
    # -----------------------------------------------------------------------------

    def scan_fun(self):
        network_scanner = nmap.PortScanner()
        network_scanner.scan('192.168.137.205', '10-443')
        print(network_scanner.all_hosts())
        print(network_scanner.scaninfo())

    # -----------------------------------------------------------------------------
    #   Compiles a list of Online IPS or the PLCs
    # -----------------------------------------------------------------------------
    # def create_list(self):

    # -----------------------------------------------------------------------------
    # Scans for network interfaces that is active on the computer
    # -----------------------------------------------------------------------------
    def is_interface_up(interface):
        addr = netifaces.ifaddresses(interface)
        return netifaces.AF_INET in addr


nm = NetworkScanner()
nm.create_record()
nm.interfaces()
nm.create_record()

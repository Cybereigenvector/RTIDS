# ----------------------------------------------------------------
# This module scans the network of the IDS to detect
# other instances of IDS running on the network. This
# scanning module also creates a list of active clients.
# By:- Rishabh Das
# ----------------------------------------------------------------
import netifaces


class Scanner:

    # ----------------------------------------------------------------------------
    # Init function that initializes the functions and the variables when the
    # scanner is called from its instance
    # ----------------------------------------------------------------------------
    def __init__(self, range, port):
        self.ip_range = range  # Provides the Ip addresses of the network to be scanned
        self.port_range = port  # provides a list of ports to be scanned, if the list is
        # empty all ports are scanned

    # --------------------------------------------------------------------------------
    # This functions finds all the interfaces. The Associated IP addresses and the
    # MAC addresses with that interfaces and compiles a dictionary
    #
    # These numbers are for troubleshooting, in reality AF_LINK or AF_INET would be used
    # directly to access the information
    # 17-> AF_LINK - This is the link layer interface and the MAC Address is recorded
    #      from this interface
    # 2 -> AF_INET - This is the normal internet interface and the IP address is
    #      recorded from this interface
    # 10-> IPv6 - This is not considered in this IPS code. The IPS can only handle
    # --------------------------------------------------------------------------------
    def interfaces(self):
        mac_list = []
        ip_list = []
        interface_list = netifaces.interfaces()
        print ("The number of interfaces connected to the computer is " + str(len(interface_list)))
        print(interface_list)
        for i in interface_list:
            addrs = netifaces.ifaddresses(i)
            link = netifaces.AF_LINK
            internet = netifaces.AF_INET
            for k, v in addrs.items():
                find = True
                if k is link:
                    for x in v:
                        if 'addr' in x:
                            mac_list.append(x['addr'])
                        else:
                            print('blah')
                elif k is internet:
                    for x in v:
                        if 'addr' in x:
                            print(x)
                            ip_list.append(x['addr'])
                        else:
                            print('Blah Internet')
        #print(ip_list)
        #print(mac_list)


            # print(mac_list)
            # print(addrs[2])
            # print(addr[netifaces.AF_LINK])
            # print(netifaces.ifaddresses(i))



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


nm = Scanner(123, 123)
nm.interfaces()

# ----------------------------------------------------------------
#
# -> Finds all the interfaces in the computer
# -> Finds the IP addresses of the connected interfaces
# -> Finds the active PLCs in the found interfaces
#
# Future:-
# -> Finds the active
# By:- Rishabh Das
# ----------------------------------------------------------------
import netifaces

class NetworkScanner:

    # ----------------------------------------------------------------------------
    # Init function that initializes the functions and the variables when the
    # scanner. The instance variables are initialized in this function
    # ----------------------------------------------------------------------------

    def __init__(self,port='502',ips='200.200.200.1',plc='100.100.100.1'):
        self.mac_list = []
        self.ip_list = []
        self.interface_list = netifaces.interfaces()

        self.loop_back = ''
        self.connected_interface_ip = []
        self.connected_interface_index = []
        self.scan_ip = []
        self.port_range = port
        self.ips_ip = ips
        self.plc_ip = plc

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
    # The IP addresses and the MAC Addresses are formatted by this function
    # ------------------------------------------------------------------------------

    def format_addr(self):
        self.loop_back = self.ip_list[self.interface_list.index('lo')]
        count = 0
        for i in self.ip_list:
            count = count + 1
            if i is not self.loop_back and i is not 'NA':
                self.connected_interface_ip.append(i)
                self.connected_interface_index.append(count)
        for i in self.connected_interface_ip:
            count = 0
            temp=''
            for c in i:
                if count < 3:
                    temp = temp + c
                else:
                    temp = temp + '1'
                    self.scan_ip.append(temp)
                    break
                if c is '.':
                    count = count + 1

    # ------------------------------------------------------------------------------
    # This function summarizes the findings of all the functions
    # ------------------------------------------------------------------------------

    def show_summary(self):
        print("================================SUMMARY================================")
        print("Connected interfaces - >", self.interface_list)
        print("MAC addresses of the interfaces - >", self.mac_list)
        print("IP addresses associated with the interfaces - >", self.ip_list)
        print("Active interface IPs - >",self.connected_interface_ip)
        print("IP range being scanned - >",self.scan_ip)
        print("Port range being scanned - >", self.port_range)
        print("IPS network - >",self.ips_ip)
        print("PLC network - >", self.plc_ip)
        print("List of active PLCs - >")


    # ------------------------------------------------------------------------------
    # This function creates record of the Mac addresses and the IP addresses
    # ------------------------------------------------------------------------------

    def create_record(self):
        if self.mac_list == [] or self.ip_list== []:
            print ("The lists are empty !! \nNothing to Write")
        else:
            print("Writing to file!!!")
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


nm = NetworkScanner('10-1000')
nm.create_record()
nm.interfaces()
nm.create_record()
nm.format_addr()
nm.show_summary()

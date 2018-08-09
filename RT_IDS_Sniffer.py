# ----------------------------------------------------------------
# This is the sniffer module of the IPS. All incoming packets into
# the IPS is sniffed by this module and a database having all
# information about the incoming packets are compiled into that
# database. The Data that is saved on to the data base is also
# parsed and interpreted by this module
# -> Sniffs the traffic from the designated interface
# -> Compiles the data base and makes it accessible to the machine
# learning program
#
# Future Plans:-
# -> The program needs to generic so that new protocols can be incorporated
#  into the program whenever necessary
# -> This program needs to communicate with the web interface so that
#   features can be selected
#
# Dependencies:-
# -> pyshark
# By:- Rishabh Das
# ----------------------------------------------------------------


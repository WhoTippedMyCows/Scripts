# Sniff wireless packets

# Setup monitor mode:
# ifconfig wlan0 down
# iwconfig wlan0 mode monitor
# ifconfig wlan0 up
# iwconfig

from scapy.all import *

def get_packets(packet):
	if packet.haslayer(Dot11):
		if packet.type == 0 and packet.subtype == 8:
			print("BSSID: "+packet.addr2, 
				  "ESSID: "+packet.info,
				  "Interval: "+str(packet.beacon_interval),
				  "Timestamp: "+str(packet.timestamp))

sniff(iface="wlan0", prn=get_packets)



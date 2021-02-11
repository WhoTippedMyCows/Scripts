# Sniff 802.11 Management Frames
# Send frames to Graylog

# Setup monitor mode:
# ifconfig wlan0 down
# iwconfig wlan0 mode monitor
# ifconfig wlan0 up
# iwconfig

from scapy.all import *
import requests

def get_packets(packet):
	if packet.haslayer(Dot11):
		if packet.type == 0:

			try:
				dbm_sig = packet.dBm_AntSignal
			except:
				dbm_sig = "N/A" 

			try:
				freq = packet[RadioTap].ChannelFrequency
			except:
				freq = "N/A"

			try:
				base = 2407
				if _freq//1000 == 5:
					base = 5000
				channel = (freq - base)//5
			except:
				channel = "N/A"

			data = {

				"version": "1.1",
				"host": "kali",
				"short_message": "wireless capture frame",
				"_essid": "%s" % packet.info,
				"_signal": "%s" % dbm_sig,
				"_channel": "%s" % channel,
				"_frequency": "%s" % freq,
			}

			if packet.haslayer(Dot11AssoReq):
				data['_type'] = "asso_req"
				data['_capabilities'] = str(packet.cap)
				data['_listen_interval'] = packet.listen_interval

			elif packet.haslayer(Dot11AssoResp):
				data['_type'] = "asso_respo"
				data['_capabilities'] = str(packet.cap)
				data['_status'] = packet.status
				data['_aid'] = packet.AID

			elif packet.haslayer(Dot11Auth):
				data['_type'] = "auth"
				data['_status'] = packet.status
				data['_algo'] = packet.algo
				data['_seqnum'] = packet.seqnum

			elif packet.haslayer(Dot11Deauth):
				data['_type'] = "deauth"
				data['_reason'] = packet.reason

			elif packet.haslayer(Dot11Disas):
				data['_type'] = "disas"
				data['_reason'] = packet.reason

			elif packet.haslayer(Dot11Beacon):
				data['_beacon_interval'] = packet.beacon_interval
				data['_capabilities'] = str(packet.cap)
				data['_timestamp'] = packet.timestamp
				data['_type'] = "beacon"

			elif packet.haslayer(Dot11ProbeReq):
				data['_type'] = "probe_req"

			elif packet.haslayer(Dot11ProbeResp):
				data['_type'] = "probe_resp"
				data['_beacon_interval'] = packet.beacon_interval
				data['_capabilities'] = str(packet.cap)
				data['_timestamp'] = packet.timestamp

			send_data(data)


def send_data(log_data):

	r = requests.post('http://172.20.4.56:12201/gelf', json=log_data)
	if r.status_code != 202:
		print("Error - HTTP code: %s" % str(r.status_code))


sniff(iface="wlan0", prn=get_packets)

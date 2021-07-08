import pyshark
import time
import re
import sys
import nest_asyncio
import json

nest_asyncio.apply()


def print_time_diffs(smf_times, bgp_times):	
	if len(bgp_times) != len(smf_times):
		print(len(bgp_times), len(smf_times))
		print("->>>>>>>>>>     BGP times length do not match smf times length")
	else:
		for i in range(len(bgp_times)):
			diff_time = float(bgp_times[i]) - float(smf_times[i])
			if diff_time > 0.2:
				print("->>>>> Higher control plane convergence")
			print("\t time BGP: {} \t time SMF: {} \t time_diff : {}".format(bgp_times[i], smf_times[i], diff_time))

def populate_time_diffs(smf_times, bgp_times):
	time_diffs = []
	if len(bgp_times) == len(smf_times):
		for i in range(len(bgp_times)):
			time_diffs.append({
				"smf-time": smf_times[i],
				"bgp-time": bgp_times[i],
				"time-diff": float(bgp_times[i]) - float(smf_times[i])
			})
	return time_diffs

def get_ue_seid_tup(capture_file, ue_subnet):
	ue_details = []
	cap = pyshark.FileCapture(capture_file, display_filter='''(pfcp.msg_type == 50) && (pfcp.ue_ip_addr_ipv4 == {})'''.format(ue_subnet))
	for pkt in cap:
		m = re.findall("SEID: (\S+)", str(pkt.pfcp))
		if m is not None:
			ue_details.append((m[1], pkt.pfcp.ue_ip_addr_ipv4))
	return ue_details

def get_ctrl_pkt_times(capture_file, seid):
	cap = pyshark.FileCapture(capture_file, display_filter='''(pfcp.apply_action.buff == 1) && (pfcp.seid == {}) && (pfcp.msg_type == 52)'''.format(seid))
	times = []
	for pkt in cap:
		times.append(pkt.sniff_timestamp)
	return times

def get_bgp_time_stamps(capture_file, ue_ip):
	cap = pyshark.FileCapture(capture_file, display_filter='''((bgp.mp_unreach_nlri_ipv4_prefix == {}) && (bgp.label_stack == "0 (withdrawn)")) && (ipv6.dst == 5:5::5:5)'''.format(ue_ip))
	times = []
	for pkt in cap:
		times.append(pkt.sniff_timestamp)
	return times[:-1]

def fetch_paged_UEs(capture_file, ue_details):
	ue_paged = []
	for item in ue_details:
		cap = pyshark.FileCapture(capture_file, display_filter='''(pfcp.msg_type == 56) && (pfcp.seid == {})'''.format(item[0]))
		for pkt in cap:
			paged = (item[0], item[1])
			if paged not in ue_paged:
				ue_paged.append(paged)
	return ue_paged


def driver(smf_cap, bgp_cap, UE_range):
	results = {}
	all_ue_details = get_ue_seid_tup(smf_cap, UE_range)
	ue_details = fetch_paged_UEs(smf_cap, all_ue_details)
	print("out of {} UEs, {} participated in paging".format(len(all_ue_details), len(ue_details)))
	for tup in ue_details:
		print("UE: {} \t SEID: {}".format(tup[0], tup[1]))
		smf_times = get_ctrl_pkt_times(smf_cap, tup[0])
		bgp_times = get_bgp_time_stamps(bgp_cap, tup[1])
		print_time_diffs(smf_times, bgp_times)
		if len(bgp_times) > 0:
			results[tup[1]] = {
				"SEID": tup[0],
			}
			results[tup[1]]["times"] = populate_time_diffs(smf_times, bgp_times)
	return results

if len(sys.argv) != 4:
	print("Please run the script as follows")
	print('''
				Usage:
				python3 ctrl_perf.py <smf_pkt_capture> <bgp_pkt_capture> <UE_range_prefix>

				example:
				python3 ctrl_perf.py ctrl.pcap bgp.pcap 172.16.4.0/24


				example:
				python3 ctrl_perf.py ctrl.pcap bgp.pcap 172.16.4.2

			''')
else:
	results = driver(sys.argv[1], sys.argv[2], sys.argv[3])
	with open('results.json', 'w') as res:
		json.dump(results, res)
	


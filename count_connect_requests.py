import asyncio
import sys
from collections import Counter, defaultdict
from pathlib import Path
from statistics import fmean, median, pvariance

import pyshark


ADVERTISING_PDUS = {"0x00", "0x02", "0x06", "0x07"} # ADV_IND , ADV_NONCONN_IND, ADV_SCAN_IND , ADV_EXT_IND

RSSI_WINDOW = 2          # seconds at the start and end of each MAC's history
MIN_PACKETS = 10        # minimum samples in each window
MAX_MAC_GAP = 0.5       # maximum gap between old and new MACs, in seconds
RSSI_TOLERANCE = 5      # maximum RSSI difference, in dB
EVENT_GAP = 0.005       # advertisements within 5 ms may belong to one event
TREND_WINDOW = 1        # seconds in each RSSI evolution window
TOP_K = 3               # maximum number of candidates to display
MIN_MARGIN = 0.1        # minimum score difference from the second candidate
MAX_TIMING_DISTANCE = 0.5
 

def signal_stats(values): 
    variance = pvariance(values) # calculate the population variance using py statistics module.
    # This is because two machines might have the same mean but a much larger variance; therefore, one should look not only at the mean but also at the variance.
    return {"median": median(values), "mean": fmean(values), "variance": variance,
            "std": variance ** 0.5, "min": min(values), "max": max(values)}


def window_profile(packets): 
    events = []
    for time, rssi in packets:
        if not events or time - events[-1] > EVENT_GAP:
            events.append(time)
    gaps = [second - first for first, second in zip(events, events[1:])]
    timing = signal_stats(gaps) if len(gaps) >= 2 else None
    rate = len(gaps) / (events[-1] - events[0]) if gaps else None
    return {"rssi": signal_stats([rssi for time, rssi in packets]),
            "timing": timing, "events": len(events), "rate": rate}


def rssi_evolution(packets):
    buckets = defaultdict(list)
    first = packets[0][0]
    for time, rssi in packets:
        buckets[int((time - first) / TREND_WINDOW)].append((time, rssi))
    series = []
    for index, samples in sorted(buckets.items()):
        if len(samples) >= 3:
            point = signal_stats([rssi for time, rssi in samples])
            point["index"] = index
            point["time"] = median(time for time, rssi in samples)
            point["count"] = len(samples)
            series.append(point)
    return series


def profile_distance(old, new): 
    rssi_distance = fmean(abs(old["rssi"][key] - new["rssi"][key]) / RSSI_TOLERANCE # Calculate the absolute difference between the medians, the means, and the standard deviations
                          for key in ("median", "mean", "std"))
    timing_distance = None
    if old["timing"] is not None and new["timing"] is not None:
        timing_distance = fmean(                                  #  Calculate the absolute difference between the medians, the means, and the standard deviations of the intervals (timing)
            abs(old["timing"][key] - new["timing"][key]) /
            max(old["timing"][key], new["timing"][key], 0.001)
            for key in ("median", "mean", "std"))
    return rssi_distance, timing_distance # low value indicate that rssi profile are similar


def candidate_reasons(old, new, capture_end): # check constarint - all MAC has 10 elem, old MAC disappear before new , the new appear befor 500 ms 
    reasons = []
    if min(old["start_count"], old["end_count"]) < MIN_PACKETS:
        reasons.append("old_samples")
    if min(new["start_count"], new["end_count"]) < MIN_PACKETS:
        reasons.append("new_samples")
    if capture_end - new["first"] < RSSI_WINDOW:
        reasons.append("followup")
    gap = new["first"] - old["last"] # calcolate the gap  
    if gap <= 0:
        reasons.append("overlap")
    elif gap > MAX_MAC_GAP:
        reasons.append("gap")
    return reasons


def rank_mac_candidates(tracks, capture_end): 
    rankings = defaultdict(list)
    for new_mac, new in tracks.items():  # 2 loops the first select a mac as new address 
        if min(new["start_count"], new["end_count"]) < MIN_PACKETS:
            continue
        if capture_end - new["first"] < RSSI_WINDOW:
            continue
        for old_mac, old in tracks.items(): # secondo loop search on other mac a old address 
            if candidate_reasons(old, new, capture_end):
                continue
            gap = new["first"] - old["last"]
            difference = abs(new["start_rssi"] - old["end_rssi"])
            rssi_distance, timing_distance = profile_distance(old["end_profile"], new["start_profile"])
            parts = [rssi_distance, gap / MAX_MAC_GAP]    # this is the main part of the ranking , rssi distance (how similar they are), how close are on timing , and ho similar are the advertising frequency
            if timing_distance is not None:
                parts.append(timing_distance)
            rankings[new_mac].append({  #after calculating saves the result 
                "mac": old_mac, "joint_score": fmean(parts), "gap": gap,
                "rssi_difference": difference, "rssi_distance": rssi_distance,
                "timing_distance": timing_distance,
                "baseline_score": difference / RSSI_TOLERANCE + gap / MAX_MAC_GAP,
            })
    for matches in rankings.values(): # order the result 
        for item in matches:
            item["score"] = item["joint_score"]
        matches.sort(key=lambda item: (item["score"], item["mac"]))
    return dict(rankings)


def mac_change_decisions(rankings, use_rssi=True, use_timing=True):
    by_old_mac = defaultdict(list)
    for new_mac, matches in rankings.items():
        for match in matches:
            by_old_mac[match["mac"]].append((match["score"], new_mac))
    for matches in by_old_mac.values():
        matches.sort()
    changes = {}
    decisions = {}
    for new_mac, matches in rankings.items():
        best = matches[0] # matchers[0] is the old MAC withe the lowest score 
        reasons = []  #reason why is rejected
        rssi_gap = best["rssi_difference"]
        if use_rssi and rssi_gap > RSSI_TOLERANCE: #The absolute difference between the RSSI medians of the two MACs must not exceed 5 dB.
            reasons.append("rssi")
        if use_timing and best["timing_distance"] is not None and best["timing_distance"] > MAX_TIMING_DISTANCE: #the normalized statistical distance between advertising intervals must not exceed 0.5, if available
            reasons.append("timing")
        forward_margin = matches[1]["score"] - best["score"] if len(matches) > 1 else None
        if forward_margin is not None and forward_margin < MIN_MARGIN: # the program reject the associations with a big margin  
            reasons.append("forward_margin")
        reverse = by_old_mac[best["mac"]]
        if reverse[0][1] != new_mac:
            reasons.append("reverse_choice")
        reverse_margin = reverse[1][0] - reverse[0][0] if len(reverse) > 1 else None
        if reverse_margin is not None and reverse_margin < MIN_MARGIN:
            reasons.append("reverse_margin")
        decisions[new_mac] = {"reasons": reasons, "best_mac": best["mac"], "rssi_gap": rssi_gap,
                              "forward_margin": forward_margin, "reverse_margin": reverse_margin,
                              "reverse_best_new": reverse[0][1]}
        if not reasons: #if reasons is empty means that MAC change can happen
            changes[new_mac] = best["mac"]
    return changes, decisions


def analyze_rssi(rows): #
    by_mac = defaultdict(list) # this is cool whene a key doest exist py create a empty list associated at this key 
    for time, mac, rssi in sorted(rows): # sort from the first elem time 
        by_mac[mac].append((time, rssi))

    tracks = {}
    for mac, packets in by_mac.items():
        first, last = packets[0][0], packets[-1][0] # takes last and his timestamp 
        start_packets = [(time, rssi) for time, rssi in packets if time < first + RSSI_WINDOW] #seelection of the initial and final RSSI windows
        end_packets = [(time, rssi) for time, rssi in packets if time >= last - RSSI_WINDOW]  
        start_profile = window_profile(start_packets)
        end_profile = window_profile(end_packets)
        series = rssi_evolution(packets)
        tracks[mac] = {
            "first": first, "last": last, "packets": len(packets),
            "start_count": len(start_packets), "end_count": len(end_packets),
            "start_rssi": start_profile["rssi"]["median"],
            "end_rssi": end_profile["rssi"]["median"],
            "start_profile": start_profile, "end_profile": end_profile,
            "series": series,
        }
    capture_end = max((track["last"] for track in tracks.values()), default=0)
    rankings = rank_mac_candidates(tracks, capture_end)
    changes, decisions = mac_change_decisions(rankings)
    return tracks, changes, rankings


def report_rssi(rows):
    if not rows:
        print("  RSSI analysis: no advertisements with an address and usable RSSI")
        return
    tracks, changes, rankings = analyze_rssi(rows)
    first_time = min(track["first"] for track in tracks.values())
    print("  RSSI and timing: experimental estimate for relatively stable radio conditions")
    profile_count = 0
    for mac, track in tracks.items():
        if min(track["start_count"], track["end_count"]) < MIN_PACKETS:
            continue
        profile_count += 1
        print(f"    {mac}: {track['packets']} advertisements, "
              f"{track['first'] - first_time:.3f}-{track['last'] - first_time:.3f} s, "
              f"start/end RSSI {track['start_rssi']:g}/{track['end_rssi']:g} dBm")
        for side in ("start", "end"):
            profile = track[side + "_profile"]
            rssi = profile["rssi"]
            cadence = "unavailable"
            if profile["timing"] is not None:
                cadence = f"{profile['timing']['median'] * 1000:.1f} ms"
            print(f"      {side}: RSSI std {rssi['std']:.1f} dB, "
                  f"min/max {rssi['min']:g}/{rssi['max']:g} dBm, "
                  f"median interval {cadence}")
    for new_mac, matches in rankings.items():
        print(f"    Top-{min(TOP_K, len(matches))} for {new_mac} "
              f"(temporal candidates: {len(matches)}; lower score = more similar; score is not a probability):")
        for position, match in enumerate(matches[:TOP_K], 1):
            timing = (f"{match['timing_distance']:.3f}"
                      if match["timing_distance"] is not None else "unavailable")
            print(f"      {position}. {match['mac']}: score {match['score']:.3f}, "
                  f"RSSI distance {match['rssi_distance']:.3f}, timing {timing}, "
                  f"gap {match['gap'] * 1000:.1f} ms")
        if new_mac not in changes:
            print("      association rejected: insufficient or ambiguous evidence")
    if not rankings:
        print("  No eligible temporal candidates for a MAC change.")
    for new_mac, old_mac in changes.items():
        gap = tracks[new_mac]["first"] - tracks[old_mac]["last"]
        difference = abs(tracks[new_mac]["start_rssi"] - tracks[old_mac]["end_rssi"])
        print(f"    possible MAC change: {old_mac} -> {new_mac} "
              f"(gap {gap:.3f} s, RSSI difference {difference:g} dB)")
    print(f"  Addresses with RSSI: {len(tracks)}; possible MAC changes: {len(changes)}")
    print(f"  Comparable profiles: {profile_count}; "
          f"addresses excluded due to insufficient samples: {len(tracks) - profile_count}")
    print(f"  Profile groups assuming these associations: {profile_count - len(changes)}") # the mac take all records and subtract the number of MAC accepted
    print("  The exact number of physical devices remains unknown.")


def regular_interval(events): #30 ms good intervall check the blog that explain it 
    gaps = Counter()
    for first, second in zip(events, events[1:]):
        gap = second - first
        units = round(gap / 0.00125)
        if 6 <= units <= 3200 and abs(gap - units * 0.00125) <= 0.0005:
            gaps[units] += 1
    if gaps:
        units, repeats = gaps.most_common(1)[0]
        if repeats >= 4:
            return units * 1.25, repeats
    return None


def show_timeline(links, first_time):
    if not links:
        print("  No confirmed or inferred connections available for overlap analysis.")
        return

    starts = defaultdict(list)
    ends = defaultdict(list)
    known_devices = set()
    for number, link in enumerate(links):
        starts[link["start"]].append(number)
        ends[link["last_data"][1]].append(number)
        known_devices.update(link["devices"])

    print(f"  Endpoint addresses from CONNECT_IND: {len(known_devices)}")
    print("  Observed intervals (seconds from the start of the file):")
    active = set()
    previous = None
    max_links = max_devices = 0
    for time in sorted(set(starts) | set(ends)):
        if active and previous is not None and time > previous:
            devices = set()
            for number in active:
                devices.update(links[number]["devices"])
            max_links = max(max_links, len(active))
            max_devices = max(max_devices, len(devices))
            addresses = ", ".join(links[number]["aa"] for number in sorted(active))
            word = "connection" if len(active) == 1 else "connections"
            print(f"    {previous - first_time:.3f}-{time - first_time:.3f} s: "
                  f"{len(active)} {word}, {len(devices)} known addresses ({addresses})")
        active.update(starts[time])
        active.difference_update(ends[time])
        previous = time
    word = "connection" if max_links == 1 else "connections"
    print(f"  Peak overlap of observed intervals: "
          f"{max_links} {word}, {max_devices} known endpoint addresses")
    print("  Addresses estimate devices; endpoints of inferred links are unknown.")


def analyze(file, loop):
    requests = [] # list of CONNECT_IND 
    by_aa = {} # last request observet for each AA 
    unknown = {}  # data packets without a captured CONNECT_IND
    rssi_rows = [] 
    first_time = None  # time stamp first packet 
    advertising_packets = 0 
    advertising_addresses = set() 
    advertising_without_address = 0

    with pyshark.FileCapture(str(file), keep_packets=False, eventloop=loop) as capture: # pyshark open the PCAP with TSHARK and iter on all the packet 
        for packet in capture:  # this just save the first timestamp and check tha packet that are not BLE 
            time = float(packet.sniff_timestamp) 
            if first_time is None:
                first_time = time
            if "BTLE" not in packet:
                continue
            if "BTLE_RF" in packet: # verify CRC 
                rf = packet.btle_rf
                if (rf.get_field_value("flags_crc_checked") == "True" and
                        rf.get_field_value("flags_crc_valid") == "False"):
                    continue
            if "NORDIC_BLE" in packet and packet.nordic_ble.get_field_value("crcok") == "False":
                continue

            get = packet.btle.get_field_value #check if there are one of the 4 PDU BLE 
            pdu = get("advertising_header_pdu_type")
            if pdu in ADVERTISING_PDUS:
                advertising_packets += 1
                mac = get("advertising_address") # for each packet the code find the MAC and RSI  
                if mac:
                    advertising_addresses.add(mac.lower())
                else:
                    advertising_without_address += 1

                rssi = None
                if "BTLE_RF" in packet:
                    if packet.btle_rf.get_field_value("flags_signal_dbm_valid") != "False":
                        rssi = packet.btle_rf.get_field_value("signal_dbm")
                elif "NORDIC_BLE" in packet:
                    rssi = packet.nordic_ble.get_field_value("rssi")
                if mac and rssi is not None and -127 <= int(rssi) <= 20:
                    rssi_rows.append((time, mac.lower(), int(rssi)))

            
            if pdu == "0x05":  # CONNECT_IND 
                aa = get("link_layer_data_access_address") # save access address 
                if aa is None:
                    continue
                link = { # dictionary to keep in mind everithing 
                    "aa": aa, "start": time, "data": 0, "last_data": None,
                    "nesn": None, "confirmed": False, "end": None,
                    "intervals": [], "initiator": get("initiator_address"),
                    "advertiser": get("advertising_address"),
                    "initiator_type": get("advertising_header_randomized_tx"),
                    "advertiser_type": get("advertising_header_randomized_rx"),
                }
                interval = get("link_layer_data_interval")
                if interval is not None:
                    link["intervals"].append((packet.number, int(interval) * 1.25))
                requests.append(link) # we save all in the request and in the by_aa vars
                by_aa[aa] = link
                print(f"{file.name}, frame {packet.number}: CONNECT REQUEST, "
                      f"{link['initiator']} -> {link['advertiser']}, AA {aa}")
                continue

            if get("data_header_llid") is None: # check if this AA was already here
                continue
            aa = get("access_address")
            if aa is None:
                continue
            nesn = get("data_header_next_expected_sequence_number")
            opcode = get("control_opcode")

            # 2. Data packets with the same AA and icrement the counter of packet of this AA
            if aa in by_aa: 
                link = by_aa[aa]
                link["data"] += 1
                link["last_data"] = (packet.number, time)
                if nesn is not None: # checf if the next expected sequence number is equal to the first if is != than is confirmed
                    if link["nesn"] is not None and nesn != link["nesn"]:
                        link["confirmed"] = True
                    if link["nesn"] is None:
                        link["nesn"] = nesn
                if opcode == "0x09":  # LL_FEATURE_RSP is an answare to the link protocl that tells you the supported functionlaity 
                    link["confirmed"] = True
                elif opcode == "0x00":  # LL_CONNECTION_UPDATE_IND to update the arguents of the conversetion 
                    interval = get("control_interval")
                    if interval is not None:
                        link["intervals"].append((packet.number, int(interval) * 1.25))
                elif opcode == "0x02":  # LL_TERMINATE_IND check if there is a terminated packet
                    link["end"] = (packet.number, time)
                continue

            channel = None
            if "BTLE_RF" in packet:
                channel = packet.btle_rf.get_field_value("channel")
            elif "NORDIC_BLE" in packet:
                channel = packet.nordic_ble.get_field_value("channel")
            # check if we missed the connection on the pcap    
            if aa not in unknown: # take all the info from the packets
                unknown[aa] = {
                    "aa": aa, "start": time, "first_frame": packet.number,
                    "last_data": None, "data": 0, "events": [],
                    "last_channel": None, "channels": set(), "pairs": 0,
                    "paired": False, "nesn": set(), "end": None, "devices": set(),
                }
            link = unknown[aa]
            new_event = (not link["events"] or # so if the AA is new the time elapsed is > of 0.005 the radio channel is different
                         time - link["last_data"][1] > 0.005 or
                         (channel is not None and link["last_channel"] is not None
                          and channel != link["last_channel"]))
            if new_event: # save time stamp after we will ty to find a pattern inside time stamp 
                link["events"].append(time)
                link["paired"] = False
            elif (not link["paired"] and channel is not None and # check if there is a packet with very close connection
                  0.000001 < time - link["last_data"][1] < 0.005):
                link["pairs"] += 1
                link["paired"] = True
            link["last_data"] = (packet.number, time)
            link["last_channel"] = channel
            link["data"] += 1
            if channel is not None:
                link["channels"].add(channel)
            if nesn is not None:
                link["nesn"].add(nesn)
            if opcode == "0x02":
                link["end"] = (packet.number, time)

    print(f"{file.name}: BLE advertisements {advertising_packets}; "
          f"distinct advertiser addresses {len(advertising_addresses)}; "
          f"advertisements without a readable address {advertising_without_address}")

    inferred = []    # Infer a link without a request only with periodicity and response evidence.
    # condition : no connect_ind associate with that AA
    # the event should show periodicity
    for aa, link in unknown.items():
        if aa in by_aa or len(link["events"]) < 5:
            continue
        period = regular_interval(link["events"])
        if period and (link["pairs"] >= 2 or len(link["nesn"]) >= 2):
            link["interval"], link["repeats"] = period
            inferred.append(link)

    for link in requests: # cool print
        status = "confirmed" if link["confirmed"] else "unverified"
        print(f"  {link['aa']}: {status} ({link['data']} data packets)")
        if link["confirmed"]:
            for frame, interval in link["intervals"]:
                print(f"    programmed connection interval: {interval:g} ms (frame {frame})")
        if link["end"]:
            frame, time = link["end"]
            print(f"    termination observed (LL_TERMINATE_IND): frame {frame}, "
                  f"after {time - link['start']:.2f} s")
        elif link["confirmed"]:
            print("    end not observed: the last packet does not prove disconnection")

    for link in inferred: # cool print
        print(f"{file.name}, frame {link['first_frame']}: connection inferred without CONNECT_IND, "
              f"AA {link['aa']} ({link['data']} packets, "
              f"recurring interval {link['interval']:g} ms repeated {link['repeats']} times, "
              f"{len(link['channels'])} channels)")
        if link["end"]:
            frame, time = link["end"]
            print(f"    termination observed (LL_TERMINATE_IND): frame {frame}, "
                  f"after at least {time - link['start']:.2f} s")
        else:
            print("    actual start and end are unknown; only observed packets are shown")

    word = "request" if len(requests) == 1 else "requests"
    print(f"{file.name}: {len(requests)} {word}; connections inferred without CONNECT_IND: {len(inferred)}")
    confirmed = [link for link in requests if link["confirmed"]]
    for link in confirmed:
        link["devices"] = set()
        for address, address_type in ((link["initiator"], link["initiator_type"]),
                                      (link["advertiser"], link["advertiser_type"])):
            if address:
                link["devices"].add((address.lower(), address_type))
    show_timeline(confirmed + inferred, first_time)
    report_rssi(rssi_rows)
    return len(requests), len(confirmed), len(inferred)


def main():
    files = [Path(name) if Path(name).is_file() else Path(__file__).parent / "data" / name for name in sys.argv[1:]] # first arg name of the script after the file to analyze
    if not files: # check integrity og the command  
        sys.exit("Usage: python3 count_connect_requests.py file.pcap [more_files.pcapng ...]")
    for file in files:# check integrity og the input 
        if not file.is_file():
            sys.exit(f"File not found: {file}")

    loop = asyncio.new_event_loop() # create new async loop 
    total_requests = total_confirmed = total_inferred = 0
    try:
        for file in files:
            requests, confirmed, inferred = analyze(file, loop) # for each file that needs to be analyze return 3 param 
            total_requests += requests
            total_confirmed += confirmed
            total_inferred += inferred
    finally:
        loop.close()
    print(f"Total CONNECT requests: {total_requests}; confirmed: {total_confirmed}; "
          f"connections inferred without CONNECT_IND: {total_inferred}")


if __name__ == "__main__":
    main()

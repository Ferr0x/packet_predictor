import asyncio
import sys
from pathlib import Path

import pyshark

if len(sys.argv) < 2:
    sys.exit("Uso: python count_connect_requests.py file1.pcapng [file2.pcap ...]")

files = [Path(name) for name in sys.argv[1:]]
for file in files:
    if not file.is_file():
        sys.exit(f"File non trovato: {file}")

loop = asyncio.new_event_loop()
total_requests = 0
total_confirmed = 0

for file in files:
    requests = []
    latest = {}    # ultima richiesta per ogni access address
    count = 0
    capture_start = None

    with pyshark.FileCapture(str(file), keep_packets=False, eventloop=loop) as capture:
        for packet in capture:
            timestamp = float(packet.sniff_timestamp)
            if capture_start is None:
                capture_start = timestamp

            if "BTLE" not in packet:
                continue

            if "BTLE_RF" in packet and packet.btle_rf.get_field_value("flags_crc_valid") == "False":
                continue
            if "NORDIC_BLE" in packet and packet.nordic_ble.get_field_value("crcok") == "False":
                continue

            if packet.btle.get_field_value("advertising_header_pdu_type") == "0x05":  # CONNECT_IND / AUX_CONNECT_REQ
                aa = packet.btle.get_field_value("link_layer_data_access_address")
                if aa is None:
                    continue
                request = {
                    "aa": aa,
                    "data": 0,
                    "nesn": None,
                    "confirmed": False,
                    "start": timestamp,
                    "last_data": None,
                    "intervals": [],
                    "end": None,
                    "initiator": packet.btle.get_field_value("initiator_address"),
                    "advertiser": packet.btle.get_field_value("advertising_address"),
                    "initiator_type": packet.btle.get_field_value("advertising_header_randomized_tx"),
                    "advertiser_type": packet.btle.get_field_value("advertising_header_randomized_rx"),
                }
                interval = packet.btle.get_field_value("link_layer_data_interval")
                if interval is not None:
                    request["intervals"].append((packet.number, int(interval) * 1.25))
                requests.append(request)
                latest[aa] = request
                count += 1
                total_requests += 1
                print(f"{file.name}, frame {packet.number}: CONNECT REQUEST, {request['initiator']} -> {request['advertiser']}, AA {aa}")

            elif packet.btle.get_field_value("data_header_llid") is not None:
                aa = packet.btle.get_field_value("access_address")
                if aa in latest:
                    request = latest[aa]
                    request["data"] += 1
                    request["last_data"] = (packet.number, timestamp)

                    nesn = packet.btle.get_field_value("data_header_next_expected_sequence_number")
                    if nesn is not None:
                        if request["nesn"] is None:
                            request["nesn"] = nesn
                        elif nesn != request["nesn"]:
                            request["confirmed"] = True

                    opcode = packet.btle.get_field_value("control_opcode")
                    if opcode == "0x09":  # LL_FEATURE_RSP
                        request["confirmed"] = True
                    elif opcode == "0x00":  # LL_CONNECTION_UPDATE_IND
                        interval = packet.btle.get_field_value("control_interval")
                        if interval is not None:
                            request["intervals"].append((packet.number, int(interval) * 1.25))
                    elif opcode == "0x02":  # LL_TERMINATE_IND
                        request["end"] = (packet.number, timestamp)

    for request in requests:
        aa = request["aa"]
        if request["confirmed"]:
            total_confirmed += 1
            print(f"  {aa}: confermata ({request['data']} pacchetti dati)")
        else:
            print(f"  {aa}: non verificata ({request['data']} pacchetti dati)")

        if request["confirmed"]:
            for frame, interval in request["intervals"]:
                print(f"    intervallo radio programmato: {interval:g} ms (frame {frame})")

        if request["end"] is not None:
            frame, end_time = request["end"]
            duration = end_time - request["start"]
            print(f"    terminazione osservata (LL_TERMINATE_IND): frame {frame}, dopo {duration:.2f} s")
        elif request["confirmed"]:
            print("    fine non osservata: l'ultimo pacchetto non prova la disconnessione")

    word = "richiesta" if count == 1 else "richieste"
    print(f"{file.name}: {count} {word}")

    # Contiamo solo richieste poi confermate. L'inizio e' il CONNECT_IND;
    # senza un pacchetto di chiusura, la fine resta sconosciuta.
    # Per la timeline usiamo l'ultimo pacchetto osservato come limite.
    confirmed = [request for request in requests if request["confirmed"]]
    events = {}
    all_devices = set()
    for number, request in enumerate(confirmed):
        devices = set()
        for address, address_type in (
            (request["initiator"], request["initiator_type"]),
            (request["advertiser"], request["advertiser_type"]),
        ):
            if address is not None:
                devices.add((address.lower(), address_type))
        request["devices"] = devices
        all_devices.update(devices)

        start = request["start"]
        finish = request["last_data"][1]
        events.setdefault(start, {"start": [], "end": []})["start"].append(number)
        events.setdefault(finish, {"start": [], "end": []})["end"].append(number)

    if confirmed:
        print(f"  indirizzi endpoint distinti nelle connessioni confermate: {len(all_devices)}")
        print("  intervalli osservati (CONNECT_IND -> ultimo pacchetto, secondi dall'inizio del file):")
        active = set()
        previous_time = None
        max_connections = 0
        max_devices = 0
        for timestamp in sorted(events):
            if active and previous_time is not None and timestamp > previous_time:
                devices = set()
                for number in active:
                    devices.update(confirmed[number]["devices"])
                connections = len(active)
                max_connections = max(max_connections, connections)
                max_devices = max(max_devices, len(devices))
                addresses = ", ".join(confirmed[number]["aa"] for number in sorted(active))
                label = "connessione" if connections == 1 else "connessioni"
                print(f"    {previous_time - capture_start:.3f}-{timestamp - capture_start:.3f} s: "
                      f"{connections} {label}, {len(devices)} indirizzi endpoint ({addresses})")

            active.update(events[timestamp]["start"])
            active.difference_update(events[timestamp]["end"])
            previous_time = timestamp

        label = "connessione" if max_connections == 1 else "connessioni"
        print(f"  picco ricostruito dai pacchetti catturati: {max_connections} {label}, {max_devices} indirizzi endpoint")
        print("  Gli indirizzi sono una stima dei dispositivi: un dispositivo può cambiarli.")
    else:
        print("  Nessuna connessione confermata da cui calcolare la simultaneità.")

loop.close()

label = "confermata" if total_confirmed == 1 else "confermate"
word = "richiesta" if total_requests == 1 else "richieste"
print(f"Totale: {total_requests} {word}, {total_confirmed} {label}")

import asyncio
from pathlib import Path

import pyshark


path = Path(__file__).parent / "data/raw/ble_samples"
# output = Path(__file__).parent / "data/confirmed_access_addresses.txt"

loop = asyncio.new_event_loop()
confirmed = []
total_requests = 0

for file in sorted(path.glob("*.pcap")):
    requests = {}  # access address -> direzioni dei pacchetti dati
    count = 0

    with pyshark.FileCapture(str(file), keep_packets=False, eventloop=loop) as capture:
        for packet in capture:
            if "BTLE" not in packet:
                continue

            if packet.btle.get_field_value("advertising_header_pdu_type") == "0x05":            # 0x05 op code for CONNECT_IND or AUX_CONNECT_REQ
                aa = str(packet.btle.link_layer_data_access_address)
                requests[aa] = set()
                count += 1
                total_requests += 1
                print(f"{file.name}, frame {packet.number}: CONNECT REQUEST, AA {aa}")

            elif packet.btle.get_field_value("data_header_llid") is not None:
                aa = str(packet.btle.access_address)
                if aa in requests and packet.btle_rf.flags_crc_valid != "False":
                    requests[aa].add(str(packet.btle_rf.pdu_type))

    # 2 = central -> peripheral, 3 = peripheral -> central
    for aa, directions in requests.items():
        if "2" in directions and "3" in directions:
            confirmed.append(aa)
            print(f"  {aa}: confermata (dati in entrambe le direzioni)")
        else:
            print(f"  {aa}: non verificata")
    print(f"{file.name}: {count} richieste")

loop.close()

print(f"Totale: {total_requests} richieste, {len(confirmed)} confermate")

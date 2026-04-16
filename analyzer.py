from scapy.all import rdpcap

files = {
    "Browsing (http.cap)": "http.cap",
    "ICMP/Ping (icmp.pcap)": "icmp.pcap",
    "Idle/DNS (dns.cap)": "dns.cap"
}

def get_protocol_data():
    results = {"TCP": [], "UDP": [], "ICMP": []}
    ordered_files = ["http.cap", "icmp.pcap", "dns.cap"]

    for filename in ordered_files:
        try:
            packets = rdpcap(filename)
        except FileNotFoundError:
            results["TCP"].append(0)
            results["UDP"].append(0)
            results["ICMP"].append(0)
            continue

        tcp = udp = icmp = 0

        for pkt in packets:
            try:
                if pkt.haslayer("TCP"):
                    tcp += 1
                elif pkt.haslayer("UDP"):
                    udp += 1
                elif pkt.haslayer("ICMP"):
                    icmp += 1
            except Exception:
                pass

        total = len(packets)
        results["TCP"].append(round((tcp / total) * 100, 1) if total else 0)
        results["UDP"].append(round((udp / total) * 100, 1) if total else 0)
        results["ICMP"].append(round((icmp / total) * 100, 1) if total else 0)

    return results


if __name__ == "__main__":
    for scenario, filename in files.items():
        try:
            packets = rdpcap(filename)
        except FileNotFoundError:
            print(f"\n[ERROR] File not found: {filename} — skipping.")
            continue

        tcp = udp = icmp = other = 0
        bad_packets = 0

        for pkt in packets:
            try:
                if pkt.haslayer("TCP"):
                    tcp += 1
                elif pkt.haslayer("UDP"):
                    udp += 1
                elif pkt.haslayer("ICMP"):
                    icmp += 1
                else:
                    other += 1
            except Exception:
                bad_packets += 1

        total = len(packets)
        print(f"\n--- {scenario} ---")
        print(f"{'Protocol':<10} {'Count':<10} {'Percent'}")
        print(f"{'TCP':<10} {tcp:<10} {tcp/total*100:.1f}%")
        print(f"{'UDP':<10} {udp:<10} {udp/total*100:.1f}%")
        print(f"{'ICMP':<10} {icmp:<10} {icmp/total*100:.1f}%")
        print(f"{'Other':<10} {other:<10} {other/total*100:.1f}%")
        if bad_packets > 0:
            print(f"[!] Skipped {bad_packets} malformed packet(s)")

    print("\n\n========== WEEK 5: STRESS TEST ==========")

    try:
        stress_packets = rdpcap("icmp.pcap")
        icmp_count = 0
        bad_count = 0

        for pkt in stress_packets:
            try:
                if pkt.haslayer("ICMP"):
                    icmp_count += 1
            except Exception:
                bad_count += 1

        total_stress = len(stress_packets)
        print(f"Total packets processed : {total_stress}")
        print(f"ICMP packets detected   : {icmp_count}")
        print(f"ICMP spike percentage   : {icmp_count/total_stress*100:.1f}%")
        print(f"Malformed packets skipped: {bad_count}")

        if icmp_count / total_stress > 0.70:
            print("\n[!] SPIKE DETECTED: ICMP traffic exceeds 70% — possible ping flood!")
        else:
            print("\n[OK] No spike detected. Traffic looks normal.")

    except FileNotFoundError:
        print("[ERROR] icmp.pcap not found.")

    print("\n[PASS] Script completed without crashing — error handling works.")
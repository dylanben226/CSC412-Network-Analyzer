def count_protocols(packets):
    counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    for packet in packets:
        if packet.haslayer("TCP"):
            counts["TCP"] += 1
        elif packet.haslayer("UDP"):
            counts["UDP"] += 1
        elif packet.haslayer("ICMP"):
            counts["ICMP"] += 1
        else:
            counts["Other"] += 1
    return counts

def print_results(counts):
    total = sum(counts.values())
    print(f"{Protocol':<10} {'Count':<10} {'Percent'}"
    print("-" *30)

for protocol, count in counts.items():
          percent = count / total * 100 if total > 0 else 0
    print(f"{proto:<10} {'Count':<10} {'Percent: .1f}%")
          
          packets = rdpcap("http.cap")
    counts =count_protocols(packets)
    print_results(counts)
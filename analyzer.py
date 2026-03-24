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

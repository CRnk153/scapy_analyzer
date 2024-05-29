import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP

total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0
suspicious = False

def packet_callback(p):
    global total_packets, tcp_packets, udp_packets, icmp_packets, suspicious

    if p.haslayer(TCP):
        if p[TCP].flags & (0x04 | 0x01):
            suspicious = True
            print(f"Packet has strange flag combination! (0x04 | 0x01) {p.summary()}")
        if p[TCP].dport == 88:
            print(f"Packet from http request! {p.summary()}")
            payload = str(packet[TCP].payload)

            if "GET" in payload or "POST" in payload or "HTTP" in payload:
                match = re.search(r"(?i)Host:\s(.*?)\\r\\n", payload)
                if match:
                    url = match.group(1)
                    print("HTTP Request to:", url)

            match = re.search(r"(?i)User-Agent:\s(.*?)\\r\\n", payload)
            if match:
                user_agent = match.group(1)
                print("User-Agent:", user_agent)

            match = re.search(r"(?i)HTTP/1.[01]\s(\d{3})", payload)
            if match:
                status_code = match.group(1)
                print("HTTP Status Code:", status_code)

            print("-" * 50)

    if len(p) < 20:
        print(f"Packet's length below 20! \n {p.summary()}")

    if len(p) > 1500:
        print(f"Packet's length above 1500! \n {p.summary()}")

    if p.haslayer(IP) != 0:
        if p[IP].flags:
            print(f"IP Flags set to non-zero value ({p[IP].flags}): {p.summary()}")
    print("-" * 50)

def main():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()

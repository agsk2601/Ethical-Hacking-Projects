from scapy.all import sniff, ARP, Ether, IP , TCP, UDP, ICMP, DNS, DNSQR
from colorama import Fore, Style, init
from datetime import datetime
import argparse
init(autoreset=True)

trusted_macs = {
    "00:11:22:33:44:55",
    "86:c7:81:91:ed:ed"
}
seen_macs = set()

log_file = open("logs/packet_log.txt", "a")

def log_packet(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file.write(f"[{timestamp}] {msg}\n")
    log_file.flush()

def detect_arp_spoof(pkt):
    if pkt.haslayer(ARP):
        src_mac = pkt[ARP].hwsrc
        src_ip = pkt[ARP].psrc
        if src_mac not in trusted_macs:
            log_packet(f"{Fore.RED} [!] Possible ARP spoofing from {src_ip} [{src_mac}]" )

def process_packet(pkt):
    if pkt.haslayer(Ether):
        ether = pkt[Ether]
        src = ether.src
        dst = ether.dst

        if src not in trusted_macs and src not in seen_macs:
            log_packet(f"{Fore.YELLOW}[!] packet from untrusted MAC: {src}")
            seen_macs.add(src)
        
    if pkt.haslayer(IP):
        ip = pkt[IP]
        proto = ip.proto
        log_packet(f"{Fore.CYAN} [IP] {ip.src} -> {ip.dst} Proto: {proto} ")

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            log_packet(f"{Fore.MAGENTA}[TCP] Port:{tcp.sport} -> {tcp.dport}")

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            log_packet(f"{Fore.GREEN}[UDP] Port: {udp.sport} -> {udp.dport}")
        
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            log_packet(f"{Fore.BLUE} [ICMP] {icmp}")
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dns = pkt[DNSQR]
        log_packet(f"{Fore.YELLOW}[DNS] Query for: {dns.qname.decode(errors='ignore')}")

    detect_arp_spoof(pkt)

def main():
    parser = argparse.ArgumentParser(description="Scapy Packet Sniffer")
    parser.add_argument("-i" ,"--interface" ,default="en0",  help="Interface to sniff")
    args = parser.parse_args()
    print(f"{Style.BRIGHT}{Fore.CYAN}[*] Starting Packet Sniffer (Press Ctrl+C to stop)\n")
    sniff(prn=process_packet,iface=args.interface, store=0)

if __name__ == "__main__":
    main()
    
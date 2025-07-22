#!/usr/bin/python3
import socket
import threading
import argparse
from colorama import Fore, Style


def scan_port(ip, port):
	try:
		sock= socket.socket()
		sock.settimeout(1)
		result = sock.connect_ex((ip,port))
		if result == 0:
			print(f"{Fore.GREEN}[+] Open Port {port} .{Style.RESET_ALL}")
		sock.close()
	except:
	 pass

def threader(ip, ports):
	threads = []
	for port in ports:
		t = threading.Thread(target=scan_port, args=(ip, port))
		threads.append(t)
		t.start()
	for t in threads:
	 t.join()

def get_targets(target):
	if '/' in target:
		import ipaddress
		return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
	else:
	 return [target]

def main():
	parser = argparse.ArgumentParser(description="Advanced Python Port Scanner")
	parser.add_argument("-t", "--target", required=True, help="Target IP or subnet")
	parser.add_argument("-p","--port", default="1-1024", help="Port Range ex:20-80")
	args = parser.parse_args()
	
	port_range = args.port.split("-")
	port = range(int(port_range[0]),int(port_range[1])+1)
	target = get_targets(args.target)
	for ip in target:
		print(f"\n{Fore.CYAN}Scanning {ip}...{Style.RESET_ALL}")
		threader(ip,port)

if __name__=="__main__":
	main()

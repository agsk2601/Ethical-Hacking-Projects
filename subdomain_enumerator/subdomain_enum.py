import socket
import requests
import concurrent.futures
import argparse


found_subdomains = []

def check_subdomain(subdomain, domain):
    url = f'{subdomain}.{domain}'
    full_url = f"http://{url}"

    try:
        ip = socket.gethostbyname(url)
        try:
            responce = requests.get(full_url, timeout=3)
            status = responce.status_code
        except requests.exceptions.RequestException:
            status = "No HTTP Response"
        result = f"[+] {url} ➜ {ip} [HTTP {status}]"
        print(result)
        found_subdomains.append(result)
    except socket.gaierror:
        print(f'subdomain ➜ {subdomain} for domain ➜ {domain} does not exits or not resolvable')

def enumerate_subdomains(domain, wordlist_path, output_file):
    print(f"\nStarting enumeration for: {domain}")
    
    try:
        with open(wordlist_path, 'r') as f:
           subdomains = f.read().splitlines()
    except FileNotFoundError:
        print("wordlist not found.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        for sub in subdomains:
            executor.submit(check_subdomain, sub, domain)
    if found_subdomains:
        with open(f"output/{output_file}", 'w') as out:
            out.write('\n'.join(found_subdomains))
        print(f"\n Results saved to {output_file}")
    else:
        print("\n No Subdomains Found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Subdomain Enumerator")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    parser.add_argument("-o", "--output", default="found.txt", help="Output file (default: found.txt)")
    parser.add_argument("--subfinder", action="store_true", help="Use Subfinder for additional enumeration")
    args = parser.parse_args()

    enumerate_subdomains(args.domain, args.wordlist, args.output)

    


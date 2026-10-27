import socket
from queue import Queue
from IPy import IP
import threading

open_ports = []
port_queue = Queue()
thread_list = []
banners = []

lock = threading.Lock()

def scan_TCP(target_ip, port_queue):
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                with lock:
                    open_ports.append(port)
                try:
                    banner = sock.recv(4096).decode('utf-8')
                    with lock:
                        banners.append(banner)
                except Exception:
                    pass
            else:
                pass

        except socket.gaierror:
            print("[!] Couldn't resolve the IP.")
        except socket.error:
            print("[!] Failed to connect to the server.")
        except Exception as e:
            print(f"[!] Error: {e}")

def get_hostname():
    try:
        # Ask the user for hostname/IP and port range
        target_host = input("[*] Hostname/IP: ").strip()
        target_port = input("[*] Enter the port range (e.g: 1-1024): ").strip()
        # Verify the start port and end port
        start_port, end_port = map(int, target_port.split("-"))
        # Set the port range
        port_range = range(start_port, end_port + 1)

        # Check the IP of hostname
        try:
            IP(target_host)
            target_ip = target_host
        except ValueError:
            target_ip = socket.gethostbyname(target_host)

        return target_host, target_ip, port_range
    
    except ValueError:
        print("[!] Invalid input, please check the port range or hostname/IP.")
    except KeyboardInterrupt:
        print("[*] Quiting...")
        exit(1)

def main():
    try:
        target_host, target_ip, port_range = get_hostname()
        check = target_host.replace(".", "")
        # Checking if the target host is IP or hostname
        if check.isdigit():
            print(f"[*] Scanning IP: {target_ip}")
        else:
            print(f"[*] Scanning {target_host}, IP: {target_ip}")

        # Putting the port inside port queue
        for port in port_range:
            port_queue.put(port)

        for _ in range(min(100, len(port_range))):
            thread = threading.Thread(target=scan_TCP, args=(target_ip, port_queue))
            thread_list.append(thread)
            thread.start()

        for thread in thread_list:
            # Wait for other threads complete
            thread.join()

        print("-" * 50)
        if open_ports:
            print("[*] Summary:")
            for port in sorted(open_ports):
                print(f"[+] Port {port} is open.")

            if banners:
                print("[*] Banners:")
                for banner in banners:
                    print(banner)

        else:
            print("[-] No open ports were found.")

        
    except KeyboardInterrupt:
        print("[*] Quiting...")

if __name__ == "__main__":
    main()
import socket
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor

class FastScanner:
    def __init__(self, target, threads):
        self.target = target
        self.threads = threads
        self.lock = Lock()
        self.open_ports = []

    def scan_port(self, port):
        try:
            # Create a TCP socket for the port check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            # Try to connect to the target port
            result = sock.connect_ex((self.target, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
            sock.close()
        except Exception:
            # Ignore connection errors and move to the next port
            pass

    def run(self, port_range=(1, 1024)):
        # Show the current scan range
        print(f"🔍 [SCANNING] Target: {self.target} | Ports: {port_range[0]}-{port_range[1]}")
        self.open_ports = []

        # Scan multiple ports at the same time
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            ports = range(port_range[0], port_range[1] + 1)
            executor.map(self.scan_port, ports)

        # Return the ports in ascending order
        return sorted(self.open_ports)



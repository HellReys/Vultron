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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
            sock.close()
        except Exception:
            pass

    def run(self, port_range=(1, 1024)):
        print(f"🔍 [SCANNING] Target: {self.target} | Ports: {port_range[0]}-{port_range[1]}")
        self.open_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            ports = range(port_range[0], port_range[1] + 1)
            executor.map(self.scan_port, ports)

        return sorted(self.open_ports)



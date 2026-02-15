import socket
import time
from threading import Thread, Lock

class FastScanner:
    def __init__(self, target, threads):
        self.target = target
        self.threads = threads
        self.lock = Lock()
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
            sock.close()
        except:
            pass

    def run(self, port_range=(1, 1024)):
        print(f"🔍 [SCANNING] Target: {self.target} | Ports: {port_range[0]}-{port_range[1]}")
        threads_list = []

        for port in range(port_range[0], port_range[1] + 1):
            t = Thread(target=self.scan_port, args=(port,))
            threads_list.append(t)
            t.start()

            if len(threads_list) >= self.threads:
                for t in threads_list:
                    t.join()
                threads_list = []
                time.sleep(0.01)

        for t in threads_list:
            t.join()

        return sorted(self.open_ports)



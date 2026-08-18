import socket

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2.0)
        s.connect((ip, port))

        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                s.close()
                return banner
        except socket.timeout:
            pass

        probe = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode()
        s.send(probe)

        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            s.close()
            return "Unknown Service"
        s.close()

        for line in banner.split("\n"):
            # Eliminate case sensitivity
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()

        return "Unknown Service"

    except Exception:
        return "Unknown Service"
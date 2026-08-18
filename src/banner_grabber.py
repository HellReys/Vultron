import socket

def grab_banner(ip, port):
    try:
        # Open a connection to the target service
        s = socket.socket()
        s.settimeout(2.0)
        s.connect((ip, port))

        try:
            # Some services send their banner immediately
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                s.close()
                return banner
        except socket.timeout:
            pass

        # Send a basic HTTP request if no banner was received
        probe = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode()
        s.send(probe)

        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            s.close()
            return "Unknown Service"
        s.close()

        # Look for the Server header in the response
        for line in banner.split("\n"):
            # Ignore case when checking the header
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()

        return "Unknown Service"

    except Exception:
        # Return a default value if the connection fails
        return "Unknown Service"
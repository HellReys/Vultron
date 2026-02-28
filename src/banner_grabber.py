import socket


def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        banner = s.recv(1024).decode().strip()
        if banner:
            s.close()
            return banner

        s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode().strip()
        s.close()

        for line in banner.split("\n"):
            if "Server:" in line:
                return line.replace("Server:", "").strip()

        return "Unknown Service"
    except:
        return "Unknown Service"
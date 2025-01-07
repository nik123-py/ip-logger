import socket
import pyfiglet
import sys
import nmap
from pyfiglet import Figlet

custom_fig = Figlet(font='graffiti')
ascii_banner = pyfiglet.figlet_format("Tracker")
print(ascii_banner)
print("=================================By-nik123")


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def tracker():
    print("[$]----Session started---->")
    ip = input("[?]Enter your IP to listen on: ")

    if not is_valid_ip(ip):
        print("[!] Invalid IP address.")
        sys.exit(1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
            soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            soc.bind((ip, 80))
            soc.listen(5)
            print(f"[+] Listening on {ip}:80...")

            Sc = nmap.PortScanner()

            while True:
                try:
                    conn, address = soc.accept()
                    with conn:
                        print(f"[+] IP Logged: {address[0]}")
                        try:
                            recon = Sc.scan(address[0], arguments='-O')
                            os_details = recon['scan'][address[0]]['osmatch'][0]['osclass'][0]['osfamily']
                            print(f"{address[0]} OS details: {os_details}")
                        except Exception as e:
                            print(f"[!] Error during Nmap scan: {e}")
                except KeyboardInterrupt:
                    print("[^] <----Interrupt occurred. Terminating session---->")
                    break
                except Exception as e:
                    print(f"[!] Error handling connection: {e}")

    except socket.error as e:
        print(f"[!] Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    tracker()

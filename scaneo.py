import socket
import ipaddress
from ipwhois import IPWhois

# Puertos comunes a escanear
common_ports = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    8080: 'HTTP-Alt'
}

def get_ip_from_url(url):
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        print("No se pudo resolver la URL.")
        return None

def is_private_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj.is_private

def scan_ports(ip):
    print("\nEscaneando puertos comunes...")
    print("Puertos abiertos:")
    for port, name in common_ports.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"  - {port}/tcp ({name})")

def main():
    url = input("Ingresa la URL (sin http/https): ")
    ip = get_ip_from_url(url)

    if not ip:
        return

    print(f"\nIP resuelta: {ip}")
    
    if is_private_ip(ip):
        ip_type = "Privada"
        rango = "IP Privada"
    else:
        ip_type = "Pública"
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            rango = results.get('network', {}).get('name', 'IP Pública')
        except:
            rango = "IP Pública"

    print(f"Tipo: {ip_type}")
    print(f"Rango de IP: {rango}")

    scan_ports(ip)

if __name__ == "__main__":
    main()

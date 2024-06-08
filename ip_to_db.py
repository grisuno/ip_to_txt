import concurrent.futures
import requests
from bs4 import BeautifulSoup
import socket
import sqlite3

# Función para verificar si una dirección IP es privada
def is_private_ip(ip_int):
    private_ranges = [
        (ip_to_int('10.0.0.0'), ip_to_int('10.255.255.255')),
        (ip_to_int('172.16.0.0'), ip_to_int('172.31.255.255')),
        (ip_to_int('192.168.0.0'), ip_to_int('192.168.255.255'))
    ]
    for start, end in private_ranges:
        if start <= ip_int <= end:
            return True
    return False

# Función para convertir una dirección IP en un nombre de dominio
def ip_to_domain(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror:
        return None

# Función para procesar la página web y extraer información
def process_page(domain):
    try:
        print(f"Procesando página: {domain}")
        response = requests.get(f"http://{domain}")
        if response.status_code == 200:
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string
            print(f"Título de la página: {title}")
            return title
    except Exception as e:
        print(f"Error al procesar la página {domain}: {str(e)}")
    return None

# Función para convertir una dirección IP en un número entero
def ip_to_int(ip):
    octets = ip.split('.')
    return int(octets[0]) * 256**3 + int(octets[1]) * 256**2 + int(octets[2]) * 256 + int(octets[3])

# Función para generar direcciones IP públicas y privadas
def generate_ips(start_ip, end_ip):
    start_int = ip_to_int(start_ip)
    end_int = ip_to_int(end_ip)
    ips = []
    for ip_int in range(start_int, end_int + 1):
        ip_address = int_to_ip(ip_int)
        if is_private_ip(ip_int):
            ips.append(ip_address)
        else:
            domain = ip_to_domain(ip_address)
            if domain:
                print(f"Dirección IP: {ip_address}, Dominio: {domain}")
                title = process_page(domain)
                if title:
                    save_to_db(domain, title)
    return ips

# Función para convertir un número entero en una dirección IP
def int_to_ip(ip_int):
    return f"{ip_int >> 24 & 0xFF}.{ip_int >> 16 & 0xFF}.{ip_int >> 8 & 0xFF}.{ip_int & 0xFF}"

# Función para guardar la información en la base de datos SQLite
def save_to_db(domain, title):
    print(f"Guardando en la base de datos - Dominio: {domain}, Título: {title}")
    conn = sqlite3.connect('sites.db')
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS sites (domain TEXT, title TEXT)")
    c.execute("INSERT INTO sites VALUES (?, ?)", (domain, title))
    conn.commit()
    conn.close()

def main():
    start_ip = '1.1.1.1'
    end_ip = '255.255.255.255'
    print("Generando direcciones IP y verificando sitios web...")
    generate_ips(start_ip, end_ip)
    print("Proceso completado.")

if __name__ == "__main__":
    main()

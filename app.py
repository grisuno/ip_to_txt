import concurrent.futures

def is_private_ip(ip_int):
    # Rangos de direcciones IP privadas
    private_ranges = [
        (ip_to_int('10.0.0.0'), ip_to_int('10.255.255.255')),
        (ip_to_int('172.16.0.0'), ip_to_int('172.31.255.255')),
        (ip_to_int('192.168.0.0'), ip_to_int('192.168.255.255'))
    ]

    for start, end in private_ranges:
        if start <= ip_int <= end:
            return True
    return False

def ip_to_int(ip):
    octets = ip.split('.')
    return int(octets[0]) * 256**3 + int(octets[1]) * 256**2 + int(octets[2]) * 256 + int(octets[3])

def generate_ips(start_ip, end_ip):
    start_int = ip_to_int(start_ip)
    end_int = ip_to_int(end_ip)

    ips = []

    for ip_int in range(start_int, end_int + 1):
        if is_private_ip(ip_int):
            ips.append(int_to_ip(ip_int))
            print(f'Generated IP: {int_to_ip(ip_int)}')
    
    return ips

def int_to_ip(ip_int):
    return f"{ip_int >> 24 & 0xFF}.{ip_int >> 16 & 0xFF}.{ip_int >> 8 & 0xFF}.{ip_int & 0xFF}"

def main():
    start_ip = '1.1.1.1'
    end_ip = '255.255.255.255'

    ips = generate_ips(start_ip, end_ip)

    with open('ips.txt', 'w') as file:
        for ip in ips:
            print(f'Saving {ip} to ips.txt')
            file.write(ip + '\n')
            file.flush()

    print(f'Generated {len(ips)} IPs and saved them to ips.txt')

if __name__ == "__main__":
    main()

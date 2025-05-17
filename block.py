import subprocess

# Path to the malicious IPs file
malicious_file_path = ".\malicious.txt"

def block_ip(ip):
    """Block a single IP address using netsh command."""
    try:
        # Block the IP address using the Windows netsh firewall command
        command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block protocol=any remoteip={ip}'
        subprocess.run(command, shell=True, check=True)
        print(f"Successfully blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip}: {e}")

def read_ips(file_path):
    """Read IPs from the given file."""
    try:
        with open(file_path, 'r') as file:
            ips = file.readlines()
        return [ip.strip() for ip in ips]  # Remove extra spaces and newlines
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

def main():
    # Read the malicious IPs from the file
    malicious_ips = read_ips(malicious_file_path)
    
    # Check and block each IP
    if malicious_ips:
        for ip in malicious_ips:
            if validate_ip(ip):
                block_ip(ip)
            else:
                print(f"Invalid IP address format: {ip}")
    else:
        print("No malicious IPs found to block.")

def validate_ip(ip):
    """Validate the IP address format."""
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'  # Basic IPv4 regex
    return bool(re.match(ip_pattern, ip))

if __name__ == "__main__":
    main()

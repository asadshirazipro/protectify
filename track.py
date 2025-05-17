import sys
import requests
from collections import deque
import webbrowser
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QScrollArea, QFrame
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

# IP data cache
ip_cache = {}
def fetch_ip_data(ip_address):
    if ip_address in ip_cache:
        return ip_cache[ip_address]
    
    try:
        url = f"https://freeipapi.com/api/json/{ip_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            ip_cache[ip_address] = data
            return data
    except requests.RequestException:
        return {"error": f"Failed to retrieve data for {ip_address}"}
    return {"error": "Request failed"}

# Read last 20 unique IPs from ip.txt, skipping 192.x.x.x
def read_ips():
    unique_ips = deque(maxlen=20)
    try:
        with open("ip.txt", "r", encoding='utf-8') as file:
            lines = file.readlines()
            for line in lines[-20:]:  # Last 20 lines
                ip = line.strip()
                if (ip and 
                    not ip.startswith("192") and 
                    ip not in unique_ips):
                    unique_ips.append(ip)
    except FileNotFoundError:
        print("ip.txt not found")
    return list(unique_ips)

# Load blacklist
def load_blacklist():
    try:
        with open("blacklist.txt", "r", encoding='utf-8') as file:
            return set(line.strip() for line in file if line.strip())
    except FileNotFoundError:
        print("blacklist.txt not found")
        return set()

# Save malicious IP
def save_malicious_ip(ip):
    try:
        with open("malicious.txt", "a", encoding='utf-8') as file:
            file.write(f"{ip}\n")
    except IOError:
        print("Error writing to malicious.txt")

def open_google_maps(lat, lon):
    url = f"https://www.google.com/maps?q={lat},{lon}"
    webbrowser.open(url)

class IPDetailsApp(QWidget):
    def __init__(self):
        super().__init__()
        self.blacklist = load_blacklist()
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_ip_details)
        self.timer.start(15000)  # 15 seconds

    def init_ui(self):
        self.setWindowTitle("IP Monitor")
        self.setGeometry(100, 100, 900, 700)
        
        # Bright theme with Qt-compatible styling
        self.setStyleSheet("""
            QWidget {
                background-color: #F5F6F5;
                color: #2D3436;
                font-family: Arial;
            }
            QPushButton {
                background-color: #e3df09;
                color: red;
                border-radius: 8px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e35509;
            }
            QFrame {
                background-color: white;
                border-radius: 10px;
                border: 1px solid #DFE6E9;
                margin: 5px;
            }
        """)

        main_layout = QVBoxLayout()
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_area.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll_area)
        self.setLayout(main_layout)
        self.update_ip_details()

    def update_ip_details(self):
        unique_ips = read_ips()
        
        # Clear old widgets
        while self.scroll_layout.count():
            item = self.scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for ip in unique_ips:
            data = fetch_ip_data(ip)
            is_malicious = ip in self.blacklist
            
            if is_malicious:
                save_malicious_ip(ip)

            # Use QFrame with raised effect instead of box-shadow
            ip_frame = QFrame()
            ip_frame.setFrameShape(QFrame.Box)
            ip_frame.setFrameShadow(QFrame.Raised)
            ip_frame.setLineWidth(1)
            ip_frame.setStyleSheet("""
                border: 1px solid #DFE6E9;
                background-color: white;
                border-radius: 10px;
            """)
            ip_layout = QVBoxLayout(ip_frame)

            # IP Header
            status_color = "#E84393" if is_malicious else "#00B894"
            ip_label = QLabel(f"IP: {ip} [{'Malicious' if is_malicious else 'Safe'}]")
            ip_label.setFont(QFont('Arial', 12, QFont.Bold))
            ip_label.setStyleSheet(f"color: {status_color}; padding: 5px;")
            ip_layout.addWidget(ip_label)

            # Details
            details_text = ""
            if "error" not in data:
                details_text = "\n".join([
                    f"Country: {data.get('countryName', 'N/A')}",
                    f"City: {data.get('cityName', 'N/A')}",
                    f"ISP: {data.get('isp', 'N/A')}",
                    f"Lat: {data.get('latitude', 'N/A')}",
                    f"Lon: {data.get('longitude', 'N/A')}"
                ])
            else:
                details_text = data["error"]
                
            details_label = QLabel(details_text)
            details_label.setFont(QFont('Arial', 10))
            details_label.setStyleSheet("color: #636E72; padding: 5px;")
            ip_layout.addWidget(details_label)

            # Google Maps button
            if "latitude" in data and "longitude" in data:
                maps_btn = QPushButton("View Location on Google Maps")
                maps_btn.clicked.connect(
                    lambda ch, lat=data["latitude"], lon=data["longitude"]: 
                    open_google_maps(lat, lon)
                )
                ip_layout.addWidget(maps_btn)

            self.scroll_layout.addWidget(ip_frame)
        
        self.scroll_layout.addStretch()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IPDetailsApp()
    window.show()
    sys.exit(app.exec_())
import subprocess
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QMessageBox
from PyQt5.QtCore import QPropertyAnimation, QRect

# Function to change DNS for the specified interface
def change_dns(primary_dns, secondary_dns):
    interface_name = interface_entry.text()

    if not interface_name:
        QMessageBox.warning(window, "Input Error", "Please select a valid network interface.")
        return

    try:
        print(f"Changing DNS for interface: {interface_name}")
        # Change primary DNS
        subprocess.run(
            ["netsh", "interface", "ip", "set", "dns", interface_name, "static", primary_dns],
            check=True
        )
        # Add secondary DNS
        subprocess.run(
            ["netsh", "interface", "ip", "add", "dns", interface_name, secondary_dns, "index=2"],
            check=True
        )

        QMessageBox.information(window, "Success", f"Protection activated successfully!")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        QMessageBox.warning(window, "Error", f"An error occurred: {e}")

# Functions for different DNS options
def apply_quad9_dns():
    change_dns("9.9.9.9", "149.112.112.112")

def apply_cleanbrowsing_dns():
    change_dns("185.228.168.168", "185.228.169.169")

def apply_google_dns():
    change_dns("8.8.8.8", "8.8.4.4")

# Function to revert to ISP's default DNS
def revert_to_isp_dns():
    interface_name = interface_entry.text()

    if not interface_name:
        QMessageBox.warning(window, "Input Error", "Please select a valid network interface.")
        return

    try:
        # Revert DNS to DHCP
        subprocess.run(
            ["netsh", "interface", "ip", "set", "dns", interface_name, "dhcp"],
            check=True
        )
        QMessageBox.information(window, "Success", "Reverted to ISP's DNS.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        QMessageBox.warning(window, "Error", f"An error occurred: {e}")

# Create the application window
app = QApplication(sys.argv)
window = QWidget()
window.setWindowTitle("Protectify: Advance Firewall with DPI")

# Set Window Style
window.setStyleSheet(""" 
    QWidget {
        background-color: #2E2E2E;
        color: #FFFFFF;
        font-family: Arial, sans-serif;
    }
    QPushButton {
        background-color: #4CAF50;
        color: white;
        border: none;
        padding: 10px;
        font-size: 14px;
        margin-bottom: 10px;
        border-radius: 5px;
    }
    QPushButton:hover {
        background-color: #45a049;
    }
    QLabel {
        font-size: 16px;
        font-weight: bold;
        margin-bottom: 20px;
    }
    QLineEdit {
        background-color: #555555;
        color: white;
        padding: 10px;
        border-radius: 5px;
        font-size: 14px;
    }
    QLineEdit:focus {
        border: 2px solid #4CAF50;
    }
""")

# Create the layout
layout = QVBoxLayout()

# Set the default active interface to "WI-FI"
active_interface = "WI-FI"  # Set to "WI-FI" by default

# Create and place the interface name label
interface_name_label = f"DNS Protection on: {active_interface}"
label = QLabel(interface_name_label)
layout.addWidget(label)

# Create and place the interface input field
interface_entry = QLineEdit()
interface_entry.setText(active_interface)  # Pre-fill with the "WI-FI" interface
layout.addWidget(interface_entry)

# Create the DNS buttons
quad9_button = QPushButton("Malware+Tracker Protection")
quad9_button.clicked.connect(apply_quad9_dns)
layout.addWidget(quad9_button)

cleanbrowsing_button = QPushButton("Malware + Adult Content Protection")
cleanbrowsing_button.clicked.connect(apply_cleanbrowsing_dns)
layout.addWidget(cleanbrowsing_button)

google_button = QPushButton("General DNS Encryption")
google_button.clicked.connect(apply_google_dns)
layout.addWidget(google_button)

# Button to revert to ISP DNS
revert_button = QPushButton("Revert back to  ISP DNS")
revert_button.clicked.connect(revert_to_isp_dns)
layout.addWidget(revert_button)

# Set the layout and display the window
window.setLayout(layout)

# Apply an animation to the window
animation = QPropertyAnimation(window, b"geometry")
animation.setDuration(1000)
animation.setStartValue(QRect(200, 200, 300, 300))
animation.setEndValue(QRect(500, 200, 400, 400))
animation.start()

# Set the window size and display the window
window.resize(400, 300)
window.show()

# Run the application
sys.exit(app.exec_())

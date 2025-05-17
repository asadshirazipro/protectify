import threading
import time
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, Raw
import torch
import torch.nn as nn
import pytorch_lightning as pl
import subprocess
import os
import ctypes
from collections import deque
import customtkinter as ctk
import ipaddress

# Extract features and protocol info
def extract_packet_features(packet):
    if IP in packet:
        ip_layer = packet[IP]
        features = [
            len(packet),
            ip_layer.proto,
            int(ip_layer.src.split('.')[-1]),
            ip_layer.len,
            ip_layer.ttl
        ]
        proto = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'RAW'
        return torch.tensor(features, dtype=torch.float32), packet[IP].src, proto, packet.summary()
    return None, None, None, None

# Check if IP is private
def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# LSTM Autoencoder with dynamic threshold
class LSTMAutoencoder(pl.LightningModule):
    def __init__(self, n_features=5, timesteps=4):
        super().__init__()
        self.timesteps = timesteps
        self.n_features = n_features
        
        self.encoder = nn.LSTM(n_features, 16, batch_first=True, num_layers=1)
        self.decoder = nn.LSTM(16, 16, batch_first=True, num_layers=1)
        self.fc = nn.Linear(16, n_features)
        self.criterion = nn.MSELoss()
        self.recon_errors = deque(maxlen=1000)  # Track recent reconstruction errors

    def forward(self, x):
        encoded, _ = self.encoder(x)
        decoded, _ = self.decoder(encoded)
        return self.fc(decoded)

    def training_step(self, batch, batch_idx):
        x = batch
        x_hat = self(x)
        loss = self.criterion(x_hat, x)
        with torch.no_grad():
            error = torch.mean((x_hat - x) ** 2).item()
            self.recon_errors.append(error)
        return loss

    def configure_optimizers(self):
        return torch.optim.Adam(self.parameters(), lr=0.001)

    def get_dynamic_threshold(self):
        if not self.recon_errors:
            return 0.25  # Default threshold
        mean_error = np.mean(list(self.recon_errors))
        std_error = np.std(list(self.recon_errors))
        return mean_error + 2 * std_error  # 2 standard deviations above mean

# Background training
def train_model_in_background(data_queue, gui):
    def train():
        model = LSTMAutoencoder(n_features=5, timesteps=4)
        trainer = pl.Trainer(
            max_epochs=3,
            accelerator="auto",
            devices=1,
            logger=False,
            enable_checkpointing=False,
            enable_progress_bar=False
        )
        while True:
            if len(data_queue) >= 50:
                data = list(data_queue)[-100:]
                data_tensor = torch.stack([torch.stack(data[i:i+4]) 
                                         for i in range(len(data) - 3)])
                trainer.fit(model, torch.utils.data.DataLoader(data_tensor, batch_size=16))
                model.eval()
                gui.model = model
                gui.monitoring_queue.append(("Model updated (Threshold: {:.4f})".format(model.get_dynamic_threshold()), "blue"))
            time.sleep(5)
    
    threading.Thread(target=train, daemon=True).start()

# Anomaly detection with explanation
def detect_anomaly(model, packet_data):
    with torch.no_grad():
        input_tensor = torch.stack(packet_data).unsqueeze(0)
        recon = model(input_tensor)
        error = torch.mean((recon - input_tensor) ** 2).item()
        threshold = model.get_dynamic_threshold()
        is_anomaly = error > threshold
        return is_anomaly, error, threshold

# Block IP with private IP check
def block_ip(ip, malicious_ips, gui):
    if is_private_ip(ip):
        gui.monitoring_queue.append((f"Skipped blocking {ip} (private IP)", "gray"))
        return False
    if ip not in malicious_ips:
        try:
            subprocess.run(
                f"netsh advfirewall firewall add rule name=Block_{ip} dir=in action=block remoteip={ip}",
                shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            with open("malicious.txt", "a") as file:
                file.write(f"{ip}\n")
            malicious_ips.add(ip)
            return True
        except:
            gui.monitoring_queue.append((f"Failed to block {ip}", "red"))
            return False
    return False

# Colorful GUI with persistent IP monitoring
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.model = None
        self.root.title("AI Firewall")
        self.root.geometry("900x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.main_frame = ctk.CTkFrame(root, corner_radius=10, fg_color="#1a1a1a")
        self.main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.main_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=0)

        # Training Frame (Purple)
        self.training_frame = ctk.CTkFrame(self.main_frame, fg_color="#4a235a")
        self.training_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(self.training_frame, text="Training Data", font=("Arial", 14), text_color="#d7bde2").pack(pady=2)
        self.training_log = ctk.CTkTextbox(self.training_frame, height=400, width=280, font=("Consolas", 10), fg_color="#2d1b36", text_color="#f2e6f7")
        self.training_log.pack(fill="both", expand=True)

        # Monitoring Frame (Red)
        self.monitoring_frame = ctk.CTkFrame(self.main_frame, fg_color="#641e16")
        self.monitoring_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(self.monitoring_frame, text="IP Monitoring", font=("Arial", 14), text_color="#f5b7b1").pack(pady=2)
        self.monitoring_log = ctk.CTkTextbox(self.monitoring_frame, height=400, width=280, font=("Consolas", 10), fg_color="#3b120d", text_color="#fadbd8")
        self.monitoring_log.pack(fill="both", expand=True)

        # Traffic Frame (Green)
        self.traffic_frame = ctk.CTkFrame(self.main_frame, fg_color="#1d4d29")
        self.traffic_frame.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(self.traffic_frame, text="Traffic", font=("Arial", 14), text_color="#a9dfbf").pack(pady=2)
        self.traffic_log = ctk.CTkTextbox(self.traffic_frame, height=400, width=280, font=("Consolas", 10), fg_color="#12361e", text_color="#d5f5e3")
        self.traffic_log.pack(fill="both", expand=True)

        # Stats Frame (Blue)
        self.stats_frame = ctk.CTkFrame(self.main_frame, fg_color="#154360")
        self.stats_frame.grid(row=1, column=0, columnspan=3, pady=5, sticky="ew")
        self.tcp_label = ctk.CTkLabel(self.stats_frame, text="TCP: 0%", text_color="#a9cce3")
        self.tcp_label.pack(side="left", padx=10)
        self.udp_label = ctk.CTkLabel(self.stats_frame, text="UDP: 0%", text_color="#a9cce3")
        self.udp_label.pack(side="left", padx=10)
        self.raw_label = ctk.CTkLabel(self.stats_frame, text="RAW: 0%", text_color="#a9cce3")
        self.raw_label.pack(side="left", padx=10)

        # Data structures
        self.training_queue = deque(maxlen=100)
        self.monitoring_queue = deque(maxlen=1000)
        self.traffic_queue = deque(maxlen=100)
        self.packet_buffer = deque(maxlen=1000)
        self.data_queue = deque(maxlen=1000)
        self.unique_ips = {}
        self.malicious_ips = set()
        self.running = True
        self.proto_counts = {'TCP': 0, 'UDP': 0, 'RAW': 0}
        self.total_packets = 0

        self.load_existing_ips()
        self.start_operations()
        self.root.after(100, self.update_logs)
        self.root.after(10000, self.update_stats)

    def load_existing_ips(self):
        for file_name in ["ip.txt", "malicious.txt"]:
            if os.path.exists(file_name):
                with open(file_name, "r") as file:
                    ips = set(line.strip() for line in file)
                    if file_name == "ip.txt":
                        self.unique_ips = {ip: "Unknown" for ip in ips}
                    else:
                        self.malicious_ips = ips
                        for ip in ips:
                            if ip in self.unique_ips:
                                self.unique_ips[ip] = "UNSAFE"

    def save_unique_ip(self, ip):
        if ip not in self.unique_ips:
            self.unique_ips[ip] = "Unknown"
            with open("ip.txt", "a") as file:
                file.write(f"{ip}\n")

    def start_operations(self):
        def packet_callback(packet):
            features, src_ip, proto, summary = extract_packet_features(packet)
            if features is not None:
                self.data_queue.append(features)
                self.packet_buffer.append(features)
                self.save_unique_ip(src_ip)
                self.proto_counts[proto] += 1
                self.total_packets += 1
                self.traffic_queue.append((f"{proto} from {src_ip} ({len(packet)}B)", "white"))
                self.training_queue.append((f"Features: {features.tolist()[:2]}... ({len(self.data_queue)} samples)", "white"))
                
                if self.model and len(self.packet_buffer) >= 4:
                    batch = list(self.packet_buffer)[-4:]
                    is_malicious, error, threshold = detect_anomaly(self.model, batch)
                    status = "UNSAFE" if is_malicious else "SAFE"
                    self.unique_ips[src_ip] = status
                    if is_malicious:
                        self.monitoring_queue.append((f"{src_ip} flagged (Error: {error:.4f} > {threshold:.4f})", "orange"))
                        if block_ip(src_ip, self.malicious_ips, self):
                            self.monitoring_queue.append((f"Blocked {src_ip}", "yellow"))

        train_model_in_background(self.data_queue, self)
        threading.Thread(target=lambda: sniff(prn=packet_callback, store=0, filter="ip"), daemon=True).start()

    def update_logs(self):
        self.training_log.delete("1.0", "end")
        for msg, color in list(self.training_queue):
            self.training_log.insert("end", f"{time.strftime('%H:%M:%S')} - {msg}\n", color)
            self.training_log.tag_config(color, foreground=color)

        self.monitoring_log.delete("1.0", "end")
        self.monitoring_log.insert("end", "Unique IPs Status:\n", "white")
        self.monitoring_log.tag_config("white", foreground="white")
        for ip, status in sorted(self.unique_ips.items()):
            color = "green" if status == "SAFE" else "red" if status == "UNSAFE" else "gray"
            self.monitoring_log.insert("end", f"{ip}: {status}\n", color)
            self.monitoring_log.tag_config(color, foreground=color)
        for msg, color in list(self.monitoring_queue):
            self.monitoring_log.insert("end", f"{time.strftime('%H:%M:%S')} - {msg}\n", color)
            self.monitoring_log.tag_config(color, foreground=color)

        self.traffic_log.delete("1.0", "end")
        for msg, color in list(self.traffic_queue):
            self.traffic_log.insert("end", f"{time.strftime('%H:%M:%S')} - {msg}\n", color)
            self.traffic_log.tag_config(color, foreground=color)

        if self.running:
            self.root.after(100, self.update_logs)

    def update_stats(self):
        if self.total_packets > 0:
            tcp_pct = (self.proto_counts['TCP'] / self.total_packets) * 100
            udp_pct = (self.proto_counts['UDP'] / self.total_packets) * 100
            raw_pct = (self.proto_counts['RAW'] / self.total_packets) * 100
            self.tcp_label.configure(text=f"TCP: {tcp_pct:.1f}%")
            self.udp_label.configure(text=f"UDP: {udp_pct:.1f}%")
            self.raw_label.configure(text=f"RAW: {raw_pct:.1f}%")
        self.root.after(10000, self.update_stats)

    def on_closing(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("Please run as administrator!")
        exit()

    root = ctk.CTk()
    app = FirewallGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
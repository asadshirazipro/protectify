import scapy.all as scapy
import pandas as pd
import time
import tkinter as tk
from tkinter import ttk
import threading
from collections import deque
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation

# Initialize data structures
columns = ["packet_id", "timestamp", "ip_src", "ip_dst", "protocol", "length", "src_port", "dst_port", "data"]
packet_data = deque(maxlen=1000)  # Efficient deque for last 1000 packets
unique_ips = set()  # Set for unique IPs
packet_id_counter = 1
last_save_time = time.time()
packet_counts = deque(maxlen=60)  # Last 60 seconds of packet counts

# Function to safely decode payloads
def safe_decode(payload):
    try:
        return payload.decode(errors='replace')[:50]  # Limit data length for efficiency
    except Exception:
        return "N/A"

# Detect active network interface
def get_active_interface():
    for iface in scapy.get_if_list():
        if scapy.get_if_addr(iface) != "0.0.0.0":
            print(f"Using interface: {iface}")
            return iface
    raise Exception("No active interface found!")

# Packet processing function
def packet_callback(packet):
    global packet_id_counter, packet_data, unique_ips, last_save_time, packet_counts

    try:
        # Extract essential packet details
        ip_src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
        ip_dst = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"
        length = len(packet) if packet.haslayer(scapy.IP) else 0
        protocol = "TCP" if packet.haslayer(scapy.TCP) else "UDP" if packet.haslayer(scapy.UDP) else "Other"
        src_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else "N/A"
        dst_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else "N/A"
        data = safe_decode(packet[scapy.Raw].load) if packet.haslayer(scapy.Raw) else "N/A"

        # Create packet dictionary
        packet_info = {
            "packet_id": packet_id_counter,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "protocol": protocol,
            "length": length,
            "src_port": src_port,
            "dst_port": dst_port,
            "data": data
        }

        # Add to deque and update unique IPs
        packet_data.append(packet_info)
        if ip_src != "N/A": unique_ips.add(ip_src)
        if ip_dst != "N/A": unique_ips.add(ip_dst)

        # Update packet counts per second
        current_second = int(time.time())
        if not packet_counts or packet_counts[-1]['time'] != current_second:
            packet_counts.append({'time': current_second, 'count': 1})
        else:
            packet_counts[-1]['count'] += 1

        # Save to CSV and IPs
        save_to_csv(packet_info)
        save_unique_ips()

        # Overwrite traffic.csv every 5 minutes
        current_time = time.time()
        if current_time - last_save_time >= 300:  # 300 seconds = 5 minutes
            overwrite_traffic_csv()
            last_save_time = current_time

        # Update GUI
        update_gui(packet_info)

        packet_id_counter += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

# Save single packet to CSV (append mode)
def save_to_csv(packet_info):
    df = pd.DataFrame([packet_info])
    df.to_csv('traffic.csv', mode='a', header=not os.path.exists('traffic.csv'), index=False)

# Overwrite traffic.csv with last 1000 packets
def overwrite_traffic_csv():
    df = pd.DataFrame(packet_data)
    df.to_csv('traffic.csv', mode='w', header=True, index=False)
    print("Overwritten traffic.csv with last 1000 packets.")

# Save unique IPs to ip.txt
def save_unique_ips():
    with open('ip.txt', 'w') as f:
        f.write('\n'.join(sorted(unique_ips)))

# Update GUI with new packet
def update_gui(packet_info):
    treeview.insert("", 0, values=[packet_info[col] for col in columns], tags=('even' if packet_id_counter % 2 == 0 else 'odd',))
    if len(treeview.get_children()) > 1000:
        treeview.delete(treeview.get_children()[-1])

# Update packets-per-second plot
def update_plot(frame):
    ax.clear()
    times = [entry['time'] for entry in packet_counts]
    counts = [entry['count'] for entry in packet_counts]
    
    # Colorful scheme based on count
    colors = ['#FF6B6B' if c > 20 else '#4ECDC4' if c > 10 else '#45B7D1' for c in counts]
    ax.bar(range(len(counts)), counts, color=colors)
    
    ax.set_title("Packets per Second", fontsize=12, fontweight='bold', color='#333333')
    ax.set_ylabel("Count", fontsize=10, color='#333333')
    ax.set_xticks([])  # Hide x-axis labels for simplicity
    ax.set_facecolor('#F5F5F5')
    fig.patch.set_facecolor('#F5F5F5')

# Start sniffing in a separate thread
def start_sniffing(interface):
    print(f"Sniffing on {interface}")
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

def sniff_thread(interface):
    thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
    thread.start()

# GUI setup
def setup_gui():
    global root, treeview, fig, ax

    root = tk.Tk()
    root.title("Protectify: Advance Firewall with DPI")
    root.geometry("1200x800")
    root.configure(bg="#FFFFFF")  # Bright theme

    # Style configuration
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#FFFFFF", foreground="#333333", fieldbackground="#FFFFFF", rowheight=25)
    style.configure("Treeview.Heading", background="#E0E0E0", foreground="#333333", font=("Arial", 10, "bold"))
    style.map("Treeview", background=[('selected', '#B0E0E6')])

    # Top frame for Treeview
    top_frame = ttk.Frame(root)
    top_frame.pack(padx=10, pady=10, fill="both", expand=True)

    # Treeview setup
    treeview = ttk.Treeview(top_frame, columns=columns, show="headings", height=20)
    for col in columns:
        treeview.heading(col, text=col.capitalize(), anchor="w")
        treeview.column(col, width=130, anchor="w")
    treeview.pack(side="left", fill="both", expand=True)

    # Scrollbar
    scrollbar = ttk.Scrollbar(top_frame, orient="vertical", command=treeview.yview)
    scrollbar.pack(side="right", fill="y")
    treeview.configure(yscrollcommand=scrollbar.set)

    # Color tags for alternating rows
    treeview.tag_configure('odd', background='#F0F0F0')
    treeview.tag_configure('even', background='#FFFFFF')

    # Bottom frame for plot
    bottom_frame = ttk.Frame(root)
    bottom_frame.pack(padx=10, pady=10, fill="x")

    # Matplotlib plot setup
    fig, ax = plt.subplots(figsize=(10, 3))
    canvas = FigureCanvasTkAgg(fig, master=bottom_frame)
    canvas.get_tk_widget().pack(fill="x")
    ani = FuncAnimation(fig, update_plot, interval=1000, cache_frame_data=False)  # Update every second

    # Start sniffing
    interface = get_active_interface()
    sniff_thread(interface)

    # Schedule CSV overwrite
    root.after(300000, overwrite_traffic_csv)

    root.mainloop()

if __name__ == "__main__":
    setup_gui()
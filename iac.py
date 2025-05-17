import customtkinter as ctk
from tkinter import messagebox
import psutil
import os
import subprocess
import threading
import time
from PIL import Image
import winreg
import sys
import ctypes
import logging

# Set up logging for debugging
logging.basicConfig(filename="firewall.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class ProtectifyFirewall:
    def __init__(self, root):
        self.root = root
        self.root.title("Protectify: Firewall Internet Access Control")
        self.root.geometry("900x600")
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        # Check if Firewall service is running
        self.check_firewall_service()

        # Header with improved color scheme
        header_frame = ctk.CTkFrame(root, fg_color="#cce0ff", corner_radius=10)
        header_frame.pack(fill="x", pady=10, padx=10)
        ctk.CTkLabel(header_frame, text="Protectify: Firewall Internet Access Control", font=("Segoe UI", 24, "bold"), text_color="#004080").pack(pady=5)

        # Search bar with button
        search_frame = ctk.CTkFrame(root, fg_color="#ffffff", corner_radius=10)
        search_frame.pack(fill="x", padx=10, pady=5)
        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="Search apps...",
                                   corner_radius=8, border_width=0, fg_color="#f0f5ff", text_color="#333333")
        search_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        search_button = ctk.CTkButton(search_frame, text="Search", fg_color="#0066cc", hover_color="#004080",
                                     width=80, font=("Segoe UI", 10, "bold"), command=self.filter_apps_manual)
        search_button.pack(side="right", padx=5, pady=5)
        search_entry.bind("<KeyRelease>", self.filter_apps)

        # Main content
        self.canvas = ctk.CTkCanvas(root, bg="#f0f5ff", highlightthickness=0)
        self.scrollbar = ctk.CTkScrollbar(root, command=self.canvas.yview, fg_color="#d0e0ff")
        self.app_frame = ctk.CTkFrame(self.canvas, fg_color="#f0f5ff")
        
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True, padx=10)
        self.canvas.create_window((0, 0), window=self.app_frame, anchor="nw")
        
        self.app_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        # App data
        self.app_data = {}  # {name: {"path": path, "type": str, "status": bool, "icon": CTkImage}}
        self.app_widgets = {}

        # Start app detection
        self.running = True
        self.detect_thread = threading.Thread(target=self.detect_apps, daemon=True)
        self.detect_thread.start()

        # Update GUI
        self.root.after(1000, self.update_gui)

    def check_firewall_service(self):
        """Ensure Windows Firewall service is running"""
        try:
            result = subprocess.run("sc query mpssvc", capture_output=True, text=True, shell=True)
            if "RUNNING" not in result.stdout:
                logging.warning("Windows Firewall service is not running. Attempting to start...")
                subprocess.run("net start mpssvc", shell=True, check=True)
                logging.info("Windows Firewall service started successfully")
            else:
                logging.info("Windows Firewall service is running")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to start Firewall service: {str(e)}")
            messagebox.showerror("Error", "Windows Firewall service failed to start. Check system settings.")

    def get_app_icon(self, exe_path):
        """Load app icon, default to icon.png if not obtained"""
        try:
            import win32gui
            import win32ui
            import win32con
            large, _ = win32gui.ExtractIconEx(exe_path, 0)
            if large:
                hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
                hbmp = win32ui.CreateBitmap()
                hbmp.CreateCompatibleBitmap(hdc, 32, 32)
                hdc = hdc.CreateCompatibleDC()
                hdc.SelectObject(hbmp)
                hdc.DrawIcon((0, 0), large[0])
                win32gui.DestroyIcon(large[0])

                bmp_info = hbmp.GetInfo()
                bmp_str = hbmp.GetBitmapBits(True)
                img = Image.frombuffer('RGBA', (bmp_info['bmWidth'], bmp_info['bmHeight']), bmp_str, 'raw', 'BGRA', 0, 1)
                return ctk.CTkImage(light_image=img.resize((32, 32), Image.Resampling.LANCZOS), size=(32, 32))
        except:
            pass

        # Fallback to icon.png
        try:
            if os.path.exists("icon.png"):
                img = Image.open("icon.png").resize((32, 32), Image.Resampling.LANCZOS)
                return ctk.CTkImage(light_image=img, size=(32, 32))
        except:
            return ctk.CTkImage(light_image=Image.new('RGBA', (32, 32)), size=(32, 32))

    def get_installed_apps(self):
        """Detect installed and system apps"""
        apps = {}
        system_paths = {os.environ['SystemRoot'].lower(), os.environ['ProgramFiles'].lower()}

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['exe'] and '.exe' in proc.info['exe'].lower():
                    path = proc.info['exe']
                    name = proc.info['name'].replace('.exe', '')
                    app_type = "System" if any(path.lower().startswith(p) for p in system_paths) else "Installed"
                    apps[name] = {"path": path, "type": app_type}
            except:
                continue

        reg_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for reg_path in reg_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        path, _ = winreg.QueryValueEx(subkey, "InstallLocation")
                        if name and path and os.path.exists(path):
                            exe_path = next((f for f in os.listdir(path) if f.endswith('.exe')), None)
                            if exe_path:
                                full_path = os.path.join(path, exe_path)
                                app_type = "System" if any(full_path.lower().startswith(p) for p in system_paths) else "Installed"
                                apps[name] = {"path": full_path, "type": app_type}
                    except:
                        continue
            except:
                continue

        return apps

    def set_firewall_rule(self, app_name, app_path, enable):
        """Set firewall rule using netsh commands"""
        try:
            rule_name = f"Protectify_Block_{app_name}"
            
            # Always delete the existing rule first to ensure a clean state
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, capture_output=True, text=True)
            logging.info(f"Attempted to remove existing rule: {rule_name}")

            if not enable:  # Block traffic (OFF)
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{app_path}" enable=yes'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    logging.info(f"Successfully added block rule for {app_name} at {app_path}")
                else:
                    logging.error(f"Failed to add block rule for {app_name}: {result.stderr}")
                    messagebox.showerror("Error", f"Failed to block {app_name}: {result.stderr}")
                    return

            else:  # Allow traffic (ON)
                logging.info(f"Enabled internet for {app_name} by removing block rule")

            self.app_data[app_name]["status"] = enable
            self.update_app_status(app_name)
        except Exception as e:
            logging.error(f"Exception in set_firewall_rule for {app_name}: {str(e)}")
            messagebox.showerror("Error", f"Failed to update {app_name}: {str(e)}")

    def update_app_status(self, app_name):
        """Update GUI status and buttons"""
        widgets = self.app_widgets[app_name]
        status = self.app_data[app_name]["status"]
        widgets["status_label"].configure(text="ON" if status else "OFF", text_color="#00cc00" if status else "#ff5555")
        widgets["type_label"].configure(text=self.app_data[app_name]["type"])
        widgets["on_btn"].configure(fg_color="#00cc00" if status else "#e0e0e0", hover_color="#00aa00" if status else "#d0d0d0")
        widgets["off_btn"].configure(fg_color="#ff5555" if not status else "#e0e0e0", hover_color="#ff3333" if not status else "#d0d0d0")

    def detect_apps(self):
        """Real-time app detection with lower frequency"""
        while self.running:
            new_apps = self.get_installed_apps()
            self.root.after(0, self.update_app_list, new_apps)
            time.sleep(5)

    def filter_apps(self, event):
        """Filter apps based on search (KeyRelease)"""
        self.filter_apps_manual()

    def filter_apps_manual(self):
        """Filter apps based on search (Button click)"""
        search_term = self.search_var.get().lower()
        for widget in self.app_frame.winfo_children():
            widget.pack_forget()
        for app_name, widgets in self.app_widgets.items():
            if search_term in app_name.lower():
                widgets["frame"].pack(fill="x", padx=10, pady=5)

    def update_app_list(self, apps):
        """Update GUI with app list"""
        existing_apps = set(self.app_data.keys())
        new_apps = set(apps.keys())

        # Remove old apps
        for app_name in existing_apps - new_apps:
            self.app_widgets[app_name]["frame"].destroy()
            del self.app_widgets[app_name]
            del self.app_data[app_name]

        # Add/update apps
        for app_name in new_apps:
            if app_name not in self.app_data:
                self.app_data[app_name] = apps[app_name]
                self.app_data[app_name]["status"] = True
                self.app_data[app_name]["icon"] = self.get_app_icon(apps[app_name]["path"])
                
                frame = ctk.CTkFrame(self.app_frame, fg_color="#ffffff", corner_radius=8, border_width=1, border_color="#d0e0ff")
                frame.pack(fill="x", padx=10, pady=5)
                
                ctk.CTkLabel(frame, image=self.app_data[app_name]["icon"], text="").pack(side="left", padx=10)
                ctk.CTkLabel(frame, text=app_name, font=("Segoe UI", 12, "bold"), text_color="#333333").pack(side="left", padx=5)
                
                type_label = ctk.CTkLabel(frame, text=apps[app_name]["type"], font=("Segoe UI", 10), text_color="#666666")
                type_label.pack(side="left", padx=10)
                
                status_label = ctk.CTkLabel(frame, text="ON", font=("Segoe UI", 10, "bold"), text_color="#00cc00")
                status_label.pack(side="left", padx=10)
                
                on_btn = ctk.CTkButton(frame, text="ON", fg_color="#00cc00", width=60, font=("Segoe UI", 10, "bold"),
                                      hover_color="#00aa00", command=lambda n=app_name, p=apps[app_name]["path"]: self.set_firewall_rule(n, p, True))
                on_btn.pack(side="right", padx=5)
                
                off_btn = ctk.CTkButton(frame, text="OFF", fg_color="#ff5555", width=60, font=("Segoe UI", 10, "bold"),
                                       hover_color="#ff3333", command=lambda n=app_name, p=apps[app_name]["path"]: self.set_firewall_rule(n, p, False))
                off_btn.pack(side="right", padx=5)
                
                self.app_widgets[app_name] = {
                    "frame": frame,
                    "status_label": status_label,
                    "type_label": type_label,
                    "on_btn": on_btn,
                    "off_btn": off_btn,
                    "icon": self.app_data[app_name]["icon"]
                }
            else:
                self.update_app_status(app_name)

    def update_gui(self):
        """Periodic GUI update"""
        if self.running:
            self.root.after(1000, self.update_gui)

    def __del__(self):
        self.running = False

def is_admin():
    """Check if running with admin privileges on Windows"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if not is_admin():
        messagebox.showerror("Error", "Please run as administrator")
        sys.exit(1)
    
    root = ctk.CTk()
    app = ProtectifyFirewall(root)
    root.mainloop()
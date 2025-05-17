import sys
import subprocess
import os
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, 
                            QLabel, QHBoxLayout, QFrame, QMessageBox)
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QFont, QPalette, QPixmap, QPainter

class PythonControlApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.processes = {}

    def init_ui(self):
        # Fixed resolution
        self.setWindowTitle("Protectify:Advance Firewall with DPI")
        self.setFixedSize(1100, 720)
        
        # Clean background
        self.setStyleSheet("""
            QWidget {
                background-color: #FAFBFC;
                font-family: 'Inter';
                color: #1E2A44;
            }
        """)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(40, 20, 40, 20)

        # Title
        title = QLabel("Protectify: Advance Firewall with DPI")
        title.setFont(QFont("Inter", 22, QFont.Bold))
        title.setStyleSheet("""
            color: #FFFFFF;
            background-color: #3B82F6;
            padding: 10px;
            border-radius: 6px;
        """)
        title.setAlignment(Qt.AlignCenter)
        title.setFixedHeight(45)
        main_layout.addWidget(title)

        # Content split layout
        content_frame = QFrame()
        content_layout = QHBoxLayout(content_frame)
        content_layout.setSpacing(20)

        # Left: Team info
        team_frame = QFrame()
        team_frame.setStyleSheet("""
            background-color: #FFFFFF;
            border-radius: 5px;
            border: 1px solid #E5E7EB;
            padding: 8px;
        """)
        team_frame.setFixedWidth(600)
        team_layout = QVBoxLayout(team_frame)
        team_layout.setSpacing(10)

        # Supervisor: Zain
        zain_frame = QFrame()
        zain_layout = QHBoxLayout(zain_frame)
        zain_layout.setSpacing(15)
        zain_pic = self.load_profile_picture("zain.jpg", 70, circular=True)
        zain_layout.addWidget(zain_pic)
        zain_info = QLabel("Supervised by: Engr. Zain Ul Abideen Akhter \n(Assistant Professor The Islamia University\nof Bahawalpur)")
        zain_info.setFont(QFont("Inter", 12))
        zain_info.setStyleSheet("color: #374151;")
        zain_info.setFixedWidth(400)
        zain_info.setWordWrap(True)
        zain_layout.addWidget(zain_info)
        team_layout.addWidget(zain_frame)

        # Developers section (minimized spacing, smaller text)
        developers_frame = QFrame()
        developers_layout = QHBoxLayout(developers_frame)
        developers_layout.setSpacing(7)

        # Asad
        asad_frame = QFrame()
        asad_layout = QVBoxLayout(asad_frame)
        asad_layout.setSpacing(1)
        asad_pic = self.load_profile_picture("asad.jpg", 60, circular=False)
        asad_layout.addWidget(asad_pic)
        asad_info = QLabel("Asad Ali Akbar Shirazi\nF21BINCE1M03031")
        asad_info.setFont(QFont("Inter", 8))  # Smaller text
        asad_info.setStyleSheet("color: #374151;")
        asad_info.setAlignment(Qt.AlignCenter)
        asad_info.setFixedWidth(140)
        asad_info.setWordWrap(True)
        asad_layout.addWidget(asad_info)
        developers_layout.addWidget(asad_frame)

        # Mubashir
        mubashir_frame = QFrame()
        mubashir_layout = QVBoxLayout(mubashir_frame)
        mubashir_layout.setSpacing(1)
        mubashir_pic = self.load_profile_picture("mubashir.jpg", 60, circular=False)
        mubashir_layout.addWidget(mubashir_pic)
        mubashir_info = QLabel("Mubashir Shaheen\nF21BINCE1M03029")
        mubashir_info.setFont(QFont("Inter", 8))  # Smaller text
        mubashir_info.setStyleSheet("color: #374151;")
        mubashir_info.setAlignment(Qt.AlignCenter)
        mubashir_info.setFixedWidth(140)
        mubashir_info.setWordWrap(True)
        mubashir_layout.addWidget(mubashir_info)
        developers_layout.addWidget(mubashir_frame)

        # Hamza
        hamza_frame = QFrame()
        hamza_layout = QVBoxLayout(hamza_frame)
        hamza_layout.setSpacing(1)
        hamza_pic = self.load_profile_picture("hamza.jpg", 60, circular=False)
        hamza_layout.addWidget(hamza_pic)
        hamza_info = QLabel("Hafiz Muhammad Hamza Sohail\nF21BINCE1M03004")
        hamza_info.setFont(QFont("Inter", 8))  # Smaller text
        hamza_info.setStyleSheet("color: #374151;")
        hamza_info.setAlignment(Qt.AlignCenter)
        hamza_info.setFixedWidth(140)
        hamza_info.setWordWrap(True)
        hamza_layout.addWidget(hamza_info)
        developers_layout.addWidget(hamza_frame)

        team_layout.addWidget(developers_frame)

        # Project info
        project_info = QLabel(
            "Next-Level Network Protection\n"
            "Features: Deep Packet Inspection | AI Detection (Autoencoder + LSTM) \n |OSINT Blacklist | DNS Security"
        )
        project_info.setFont(QFont("Inter", 11))
        project_info.setStyleSheet("color: #374151; line-height: 1.4;")
        project_info.setAlignment(Qt.AlignCenter)
        project_info.setWordWrap(True)
        project_info.setFixedHeight(80)
        team_layout.addWidget(project_info)

        content_layout.addWidget(team_frame)

        # Right: Scripts and action buttons
        right_frame = QFrame()
        right_frame.setStyleSheet("""
            background-color: #FFFFFF;
            border-radius: 8px;
            border: 1px solid #E5E7EB;
            padding: 15px;
        """)
        right_frame.setFixedWidth(450)
        right_layout = QVBoxLayout(right_frame)
        right_layout.setSpacing(10)

        # Scripts section
        self.scripts = {
            1: {"script_name": "capture.py", "button_label": "DPI Detection"},
            2: {"script_name": "ML.py", "button_label": "AI Detection"},
            3: {"script_name": "iac.py", "button_label": "Internet Access Control"},
            4: {"script_name": "track.py", "button_label": "IP Tracking"},
            5: {"script_name": "block.py", "button_label": "Auto IP Blocking"},
            6: {"script_name": "dns.py", "button_label": "DNS Protection"}
        }

        self.buttons = {}
        for i in range(1, 7):
            btn = QPushButton(f"{self.scripts[i]['button_label']} - OFF")
            btn.setFixedHeight(45)
            btn.setFont(QFont("Inter", 12, QFont.Bold))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #EF4444;
                    color: #FFFFFF;
                    border-radius: 6px;
                    padding: 8px;
                    border: 2px solid #DC2626;
                }
                QPushButton:hover {
                    background-color: #F87171;
                }
            """)
            btn.clicked.connect(lambda checked, idx=i: self.toggle_script(idx))
            self.buttons[i] = btn
            right_layout.addWidget(btn)

        # Action buttons
        action_frame = QFrame()
        action_layout = QHBoxLayout(action_frame)
        action_layout.setSpacing(15)
        for text, func, color in [
            ("Traffic Log", self.open_traffic_log, "#10B981"),
            ("Docs", self.open_documentation, "#3B82F6"),
        ]:
            btn = QPushButton(text)
            btn.setFixedSize(130, 40)
            btn.setFont(QFont("Inter", 12, QFont.Bold))
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: #FFFFFF;
                    border-radius: 6px;
                    padding: 8px;
                    border: 1px solid rgba(255, 255, 255, 0.4);
                }}
                QPushButton:hover {{
                    background-color: {self.lighten_color(color)};
                }}
            """)
            btn.clicked.connect(func)
            action_layout.addWidget(btn)
        
        right_layout.addWidget(action_frame, alignment=Qt.AlignCenter)
        content_layout.addWidget(right_frame)

        main_layout.addWidget(content_frame)

        # Footer
        footer = QLabel("BS Cyber Security | Final Year Project | Fall 2021-25")
        footer.setFont(QFont("Inter", 9))
        footer.setStyleSheet("""
            color: #6B7280;
            padding: 8px;
            background-color: #FFFFFF;
            border-radius: 6px;
            border: 1px solid #E5E7EB;
        """)
        footer.setAlignment(Qt.AlignCenter)
        footer.setFixedHeight(30)
        main_layout.addWidget(footer)

        self.setLayout(main_layout)

    def load_profile_picture(self, filename, size, circular=False):
        pic = QLabel()
        if os.path.exists(filename):
            pixmap = QPixmap(filename).scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            if not pixmap.isNull():
                if circular:
                    # Create circular mask
                    mask = QPixmap(size, size)
                    mask.fill(Qt.transparent)
                    painter = QPainter(mask)
                    painter.setRenderHint(QPainter.Antialiasing)
                    painter.setBrush(QColor(255, 255, 255))
                    painter.drawEllipse(0, 0, size, size)
                    painter.end()
                    pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
                    pixmap.setMask(mask.mask())
                pic.setPixmap(pixmap)
            else:
                pic.setText("Invalid Image")
                pic.setFont(QFont("Inter", 10))
                pic.setStyleSheet("color: #EF4444; background-color: #F3F4F6; padding: 8px;")
                pic.setFixedSize(size, size)
        else:
            pic.setText("Image Not Found")
            pic.setFont(QFont("Inter", 10))
            pic.setStyleSheet("color: #EF4444; background-color: #F3F4F6; padding: 8px;")
            pic.setFixedSize(size, size)
        pic.setAlignment(Qt.AlignCenter)
        return pic

    def toggle_script(self, script_id):
        button = self.buttons[script_id]
        script_name = self.scripts[script_id]["script_name"]
        
        try:
            if button.text().endswith("OFF"):
                process = subprocess.Popen(
                    ["python", script_name],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    shell=True
                )
                self.processes[script_id] = process
                button.setText(f"{self.scripts[script_id]['button_label']} - ON")
                self.animate_button(button, "#EF4444", "#10B981")
            else:
                if script_id in self.processes:
                    self.processes[script_id].terminate()
                    del self.processes[script_id]
                button.setText(f"{self.scripts[script_id]['button_label']} - OFF")
                self.animate_button(button, "#10B981", "#EF4444")
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", f"Script '{script_name}' not found!")
        except PermissionError:
            QMessageBox.critical(self, "Error", f"Permission denied to run '{script_name}'. Run as administrator.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to toggle '{script_name}': {str(e)}")

    def animate_button(self, button, start_color, end_color):
        color_anim = QPropertyAnimation(button, b"styleSheet")
        color_anim.setDuration(500)
        color_anim.setStartValue(f"""
            background-color: {start_color};
            color: #FFFFFF; border-radius: 6px; padding: 8px; 
            border: 2px solid {self.darken_color(start_color)};
        """)
        color_anim.setEndValue(f"""
            background-color: {end_color};
            color: #FFFFFF; border-radius: 6px; padding: 8px; 
            border: 2px solid {self.darken_color(end_color)};
        """)
        color_anim.setEasingCurve(QEasingCurve.InOutCubic)
        color_anim.start()

    def open_traffic_log(self):
        try:
            subprocess.Popen(["start", "traffic.csv"], shell=True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open traffic.csv: {str(e)}")

    def open_documentation(self):
        try:
            subprocess.Popen(["start", "https://protectifyfirewall.online"], shell=True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open documentation: {str(e)}")

    def lighten_color(self, color):
        c = QColor(color)
        return QColor(min(c.red() + 40, 255), min(c.green() + 40, 255), min(c.blue() + 40, 255)).name()

    def darken_color(self, color):
        c = QColor(color)
        return QColor(max(c.red() - 40, 0), max(c.green() - 40, 0), max(c.blue() - 40, 0)).name()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(250, 251, 252))
    app.setPalette(palette)
    
    window = PythonControlApp()
    window.show()
    sys.exit(app.exec_())
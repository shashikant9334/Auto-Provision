from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, 
                            QTableWidget, QTableWidgetItem, QComboBox, QLineEdit, 
                            QHeaderView, QFrame, QApplication, QTabWidget, QSpacerItem,
                            QSizePolicy, QScrollArea, QMessageBox, QProgressDialog, QDialog, 
                            QDialogButtonBox, QCheckBox, QFormLayout)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal, QDateTime
from PyQt5.QtGui import QIcon, QColor, QFont
import socket, sqlite3
import struct
import subprocess
import re
import threading
import time
import platform
import ipaddress
import datetime
import os
import sys
import ctypes
from ctypes import wintypes
import winreg
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Prevent console window from showing
if hasattr(sys, 'frozen'):
    # Hide console in Windows
    if platform.system().lower() == 'windows':
        # This will hide the console window
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)


class NetworkScanner(QThread):
    """Thread for scanning network devices"""
    device_found = pyqtSignal(str, str, str, str)  # Added extension parameter
    scan_complete = pyqtSignal()
    
    def __init__(self, ip_range, scan_only_db_devices=False):
        super().__init__()
        self.ip_range = ip_range
        self.stop_flag = False
        self.scan_only_db_devices = scan_only_db_devices
        # Device types to skip pinging
        self.skip_device_types = ["laptop", "phone", "desktop", "tablet", "printer"]
        
    def run(self):
        try:
            # Check if IP range is in CIDR notation (e.g., 192.168.1.0/24)
            if '/' in self.ip_range:
                network = ipaddress.IPv4Network(self.ip_range, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            # Check if IP range is a single IP
            elif self.ip_range.count('.') == 3 and '-' not in self.ip_range:
                ip_list = [self.ip_range]
            # Check if IP range is in format 192.168.1.1-254
            elif '-' in self.ip_range:
                start_ip, end_range = self.ip_range.rsplit('.', 1)[0], self.ip_range.rsplit('.', 1)[1]
                if '-' in end_range:
                    start_num, end_num = map(int, end_range.split('-'))
                    ip_list = [f"{start_ip}.{i}" for i in range(start_num, end_num + 1)]
                else:
                    ip_list = [self.ip_range]
            else:
                # Default to scanning local subnet
                local_ip = self.get_local_ip()
                if local_ip:
                    subnet = local_ip.rsplit('.', 1)[0]
                    ip_list = [f"{subnet}.{i}" for i in range(1, 255)]
                else:
                    ip_list = []
            
            # If scanning only DB devices, get the list of MAC addresses from the database
            db_mac_addresses = []
            if self.scan_only_db_devices:
                db_mac_addresses = self.get_db_mac_addresses()
            
            # Scan IPs in parallel
            threads = []
            for ip in ip_list:
                if self.stop_flag:
                    break
                thread = threading.Thread(target=self.scan_ip, args=(ip, db_mac_addresses))
                thread.daemon = True
                threads.append(thread)
                thread.start()
                
                # Limit number of concurrent threads
                if len(threads) >= 20:
                    for t in threads:
                        t.join(0.1)
                    threads = [t for t in threads if t.is_alive()]
            
            # Wait for remaining threads
            for t in threads:
                t.join()
                
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            self.scan_complete.emit()
    
    def stop(self):
        self.stop_flag = True
    
    def get_local_ip(self):
        """Get the local IP address of the machine"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
    
    def get_db_mac_addresses(self):
        """Get MAC addresses from the manufacturer table in Auto.db"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT mac_address FROM brands")
            mac_addresses = [row[0].upper() for row in cursor.fetchall() if row[0]]
            conn.close()
            return mac_addresses
        except Exception as e:
            print(f"Error getting MAC addresses from DB: {e}")
            return []
    
    def scan_ip(self, ip, db_mac_addresses=None):
        """Scan a single IP address"""
        try:
            # Get hostname first to determine device type
            hostname = self.get_hostname(ip)
            
            # Check if device type should be skipped for pinging
            should_ping = True
            for device_type in self.skip_device_types:
                if device_type.lower() in hostname.lower():
                    should_ping = False
                    break
            
            # Only ping if device type is not in skip list
            if should_ping and not self.ping(ip):
                return
                
            # Get MAC address
            mac = self.get_mac_address(ip)
            
            # If scanning only DB devices, check if MAC prefix is in the list
            if self.scan_only_db_devices and db_mac_addresses:
                mac_prefix = mac.replace(":", "").replace("-", "")[:6].upper()
                found = False
                for db_mac in db_mac_addresses:
                    db_prefix = db_mac.replace(":", "").replace("-", "")[:6].upper()
                    if mac_prefix == db_prefix:
                        found = True
                        break
                if not found:
                    return
            
            # Get extension (derived from MAC address)
            extension = self.get_extension(mac)
            
            self.device_found.emit(ip, mac, hostname, extension)
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
    
    def ping(self, ip):
        """Check if an IP address responds to ping without showing console window"""
        try:
            if platform.system().lower() == 'windows':
                # Use Windows socket API directly to avoid console window
                # Create ICMP socket
                icmp = socket.getprotobyname("icmp")
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                s.settimeout(1)
                
                # Create packet
                packet_id = int((id(self) * 0xffff) & 0xffff)
                packet = b'\x08\x00\x00\x00' + packet_id.to_bytes(2, byteorder='big') + b'\x00\x00' + b'\x61' * 32
                
                # Calculate checksum
                checksum = 0
                for i in range(0, len(packet), 2):
                    if i + 1 < len(packet):
                        checksum += (packet[i] << 8) + packet[i + 1]
                    else:
                        checksum += packet[i] << 8
                checksum = (checksum >> 16) + (checksum & 0xffff)
                checksum = ~checksum & 0xffff
                
                # Insert checksum into packet
                packet = packet[:2] + checksum.to_bytes(2, byteorder='big') + packet[4:]
                
                try:
                    s.sendto(packet, (ip, 0))
                    s.recvfrom(1024)
                    return True
                except socket.timeout:
                    return False
                except:
                    return False
                finally:
                    s.close()
            else:
                # For non-Windows systems, use subprocess but hide output
                with open(os.devnull, 'w') as DEVNULL:
                    return subprocess.call(['ping', '-c', '1', '-W', '1', ip], 
                                          stdout=DEVNULL, stderr=DEVNULL) == 0
        except:
            return False
    
    def get_mac_address(self, ip):
        """Get MAC address for an IP using Windows API or ARP command with hidden console"""
        try:
            if platform.system().lower() == 'windows':
                # Use Windows API to get MAC address without spawning console
                # Initialize IP Helper API
                SendARP = ctypes.windll.Iphlpapi.SendARP
                
                # Convert IP address to 32-bit integer
                ip_addr = socket.inet_aton(ip)
                ip_int = struct.unpack("!I", ip_addr)[0]
                
                # Prepare buffer for MAC address
                buffer_size = 6
                mac_buffer = ctypes.create_string_buffer(buffer_size)
                mac_len = wintypes.ULONG(buffer_size)
                
                # Call SendARP function
                if SendARP(ip_int, 0, ctypes.byref(mac_buffer), ctypes.byref(mac_len)) == 0:
                    # Convert MAC address bytes to string
                    mac_bytes = mac_buffer.raw[:mac_len.value]
                    mac_str = ':'.join(f'{b:02X}' for b in mac_bytes)
                    return mac_str.upper()
            else:
                # For non-Windows systems, use subprocess but hide output
                with open(os.devnull, 'w') as DEVNULL:
                    output = subprocess.check_output(['arp', '-n', ip], 
                                                   stdout=subprocess.PIPE, 
                                                   stderr=DEVNULL).decode('utf-8')
                    mac_matches = re.findall(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', output)
                    if mac_matches:
                        return mac_matches[0].upper()
        except:
            pass
        return "Unknown"
    
    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    DB_PATH = "C:/Auto/Database/Auto.db"        
    
    def get_all_extensions(self):
        """Retrieve all extensions from the database."""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("SELECT display_name, username, password, domain, status, registration_time FROM extension_list")
            extensions = cursor.fetchall()
            
            conn.close()
            return extensions
        except Exception as e:
            print(f"Database error: {e}")
            return []
    
    def get_extension(self, mac):
        """Get extension based on MAC address."""
        extensions = self.get_all_extensions()  # Get the list of extensions from DB
        
        if mac and mac != "Unknown":
            mac_prefix = mac.upper()[:8]  # Take first 3 bytes for matching
            
            # Loop through the extensions and match by prefix or other criteria
            for ext in extensions:
                display_name = ext[0]  # Assuming `display_name` is the relevant field to match
                
                # If you have a specific field in `extensions` to match, adapt it here
                if mac_prefix in display_name:  # You can replace this with better matching logic if necessary
                    return ext[0]  # Return the display name or other field from the extension
                
        return "N/A"

class RefreshPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
    
        self.setWindowTitle("Network Device Scanner")
        self.setMinimumSize(1000, 700)
        self.scanner = None
        self.devices = []

        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Scroll Area to make the content scrollable
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        
        # Create a widget to contain all your main content
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        # Header Section
        header_layout = QHBoxLayout()
        
       
        # Tab Buttons
        tab_layout = QHBoxLayout()
        tab_layout.setSpacing(10)
        
       
        header_layout.addStretch()
        header_layout.addLayout(tab_layout)
        
        content_layout.addLayout(header_layout)
        
        # Filter and Action Section
        filter_frame = QFrame()
        filter_frame.setFrameShape(QFrame.StyledPanel)
        filter_frame.setStyleSheet("background-color: white; border-radius: 4px;")
        
        filter_layout = QVBoxLayout(filter_frame)
        
        # IP Range Filter
        ip_filter_layout = QHBoxLayout()
        
        ip_range_label = QLabel("IP Range:")
        
        self.ip_range_input = QLineEdit()
        self.ip_range_input.setPlaceholderText("Enter IP range (e.g., 192.168.1.0/24 or 192.168.1.1-254)")
        self.ip_range_input.setMinimumWidth(300)
        self.ip_range_input.setStyleSheet("border:1px solid gray;height:35px ;border-radius:0px")
        
        # Add checkbox for scanning only devices in manufacturer table
        self.scan_db_only_checkbox = QCheckBox("Scan only devices in manufacturer table")
        
        self.refresh_btn = QPushButton("Refresh", self)
        self.refresh_btn.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        
       
      
        ip_filter_layout.addWidget(ip_range_label)
        ip_filter_layout.addWidget(self.ip_range_input)
        ip_filter_layout.addWidget(self.scan_db_only_checkbox)
        ip_filter_layout.addWidget(self.refresh_btn)
        filter_layout.addLayout(ip_filter_layout)
        
        # Status label
        self.status_label = QLabel("Scanning network...")
        self.status_label.setStyleSheet("color: #7f8c8d;")
        filter_layout.addWidget(self.status_label)
        
        content_layout.addWidget(filter_frame)
        
        # Table Section
        table_frame = QFrame()
        table_frame.setFrameShape(QFrame.StyledPanel)
        table_frame.setStyleSheet("background-color: white; border-radius: 4px;")
        
        table_layout = QVBoxLayout(table_frame)
        
        # Search bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setMaximumWidth(300)
        self.search_input.setPlaceholderText("Filter results...")
        
        search_layout.addStretch()
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        
        table_layout.addLayout(search_layout)
        
        # Device Table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(7)  # Updated column count to include Extension and Last Updated
        headers = ["S.N.", "IP ADDRESS", "MAC ADDRESS", "EXTENSION", "HOSTNAME", "MANUFACTURER", "LAST UPDATED"]
        self.device_table.setHorizontalHeaderLabels(headers)
        self.device_table.horizontalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 5px;
                border: none;
                border-bottom: 1px solid #ddd;
                font-weight: bold;
            }
        """)
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.verticalHeader().setVisible(False)
        
        table_layout.addWidget(self.device_table)
        
        content_layout.addWidget(table_frame)
        
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)


        self.refresh_btn.clicked.connect(self.refresh_scan)
        self.search_input.textChanged.connect(self.filter_table)
        
        # Auto-detect IP range and start scan automatically
        self.auto_detect_ip_range()
        self.start_scan()
        
    DB_PATH = "C:/Auto/Database/Auto.db"
    
    def get_all_brands(self):
        """Retrieve all brands from the database."""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, mac_address FROM brands ORDER BY name")
        brands = cursor.fetchall()
        conn.close()
        return brands
    
    def auto_detect_ip_range(self):
        """Auto-detect and set the IP range based on local network"""
        local_ip = self.get_local_ip()
        if local_ip:
            subnet = local_ip.rsplit('.', 1)[0]
            ip_range = f"{subnet}.0/24"
            self.ip_range_input.setText(ip_range)
            return ip_range
        return ""
    
    def get_local_ip(self):
        """Get the local IP address of the machine"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
       
    def start_scan(self):
        """Start the network scan"""
        ip_range = self.ip_range_input.text().strip()
        if not ip_range:
            ip_range = self.auto_detect_ip_range()
            
        if ip_range:
            # Clear previous results
            self.device_table.setRowCount(0)
            self.devices = []
            
            # Get scan mode from checkbox
            scan_only_db_devices = self.scan_db_only_checkbox.isChecked()
            
            # Start the scanner
            self.scanner = NetworkScanner(ip_range, scan_only_db_devices)
            self.scanner.device_found.connect(self.add_device)
            self.scanner.scan_complete.connect(self.scan_complete)
            self.scanner.start()
            self.status_label.setText("Scanning...")
            self.refresh_btn.setEnabled(False)
        else:
            QMessageBox.warning(self, "Input Error", "Could not determine a valid IP range.")

    def refresh_scan(self):
        """Refresh the scan (stop current scan if running and start a new one)"""
        if self.scanner and self.scanner.isRunning():
            self.scanner.stop()
            
        self.start_scan()

    def scan_complete(self):
        self.status_label.setText(f"Scan complete. Found {len(self.devices)} devices.")
        self.status_label.setStyleSheet("color: #2ecc71;")
        self.refresh_btn.setEnabled(True)
    
    def add_device(self, ip, mac, hostname, extension):
        # Get current timestamp for last updated
        current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        
        # Add the device to the table and the list
        device_data = {
            'ip': ip,
            'mac': mac,
            'extension': extension,
            'hostname': hostname,
            'manufacturer': self.get_manufacturer(mac),
            'last_updated': current_time
        }
        self.devices.append(device_data)
        
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        item = QTableWidgetItem(str(row + 1))
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 0, item)
        
        item = QTableWidgetItem(ip)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 1, item)
        
        item = QTableWidgetItem(mac)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 2, item)
        
        item = QTableWidgetItem(extension)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 3, item)
        
        item = QTableWidgetItem(hostname)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 4, item)
        
        item = QTableWidgetItem(device_data['manufacturer'])
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 5, item)
        
        item = QTableWidgetItem(current_time)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 6, item)
        

    
    def filter_table(self):
        filter_text = self.search_input.text().lower()
        for row in range(self.device_table.rowCount()):
            ip_item = self.device_table.item(row, 1)
            mac_item = self.device_table.item(row, 2)
            extension_item = self.device_table.item(row, 3)
            hostname_item = self.device_table.item(row, 4)
            manufacturer_item = self.device_table.item(row, 5)
            last_updated_item = self.device_table.item(row, 6)
            
            matched = False
            if ip_item and filter_text in ip_item.text().lower():
                matched = True
            elif mac_item and filter_text in mac_item.text().lower():
                matched = True
            elif extension_item and filter_text in extension_item.text().lower():
                matched = True
            elif hostname_item and filter_text in hostname_item.text().lower():
                matched = True
            elif manufacturer_item and filter_text in manufacturer_item.text().lower():
                matched = True
            elif last_updated_item and filter_text in last_updated_item.text().lower():
                matched = True
                
            self.device_table.setRowHidden(row, not matched)
    
    

    def get_manufacturer(self, mac):
        """Get the manufacturer name based on the MAC address"""
        if mac and mac != "Unknown":
            # Extract the first 6 characters (OUI - Organizationally Unique Identifier) from the MAC address
            mac_prefix = mac.replace(":", "").replace("-", "")[:6].upper()
            
            # Fetch all brands from the database
            brands = self.get_all_brands()
            
            # Check for a matching manufacturer in the brands list
            for brand in brands:
                # The `mac_address` in the database is likely the OUI (first 6 characters)
                if mac_prefix == brand[2].replace(":", "").replace("-", "").upper()[:6]:
                    return brand[1]  # Return the manufacturer name (brand name)
        
        return 'Unknown Manufacturer'


if __name__ == "__main__":
    # Prevent console window from showing when app starts
    if platform.system().lower() == 'windows':
        # This will hide the console window
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    # Create and run the application
    app = QApplication(sys.argv)
    window = RefreshPage()
    window.show()
    sys.exit(app.exec_())
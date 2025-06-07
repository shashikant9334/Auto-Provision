from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, 
                            QTableWidget, QTableWidgetItem, QComboBox, QLineEdit, 
                            QHeaderView, QFrame, QApplication, QTabWidget, QSpacerItem,
                            QSizePolicy, QScrollArea, QMessageBox, QProgressDialog, QDialog, 
                            QDialogButtonBox)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal, QDateTime
from PyQt5.QtGui import QIcon, QColor, QFont
import socket,sqlite3,subprocess
from database import Database
import re
import threading
import platform
import ipaddress
import datetime
import logging

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
class NetworkScanner(QThread):
    """Thread for scanning network devices"""
    device_found = pyqtSignal(str, str, str)  # Added extension parameter
    scan_complete = pyqtSignal()
    DB_PATH = "C:/Auto/Database/Auto.db" 
     # Use the provided database path

    def __init__(self, ip_range, scan_all_devices=False):
        super().__init__()
        self.ip_range = ip_range
        self.scan_all_devices = scan_all_devices
        # Device brands and MAC address prefixes to scan for
        self.valid_mac_prefixes = self.get_all_brands()
        

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
            
            # Scan IPs in parallel
            threads = []
            for ip in ip_list:
                
                thread = threading.Thread(target=self.scan_ip, args=(ip,))
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
            logging.info(f"Scan error: {e}")
        finally:
            self.scan_complete.emit()

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
    
    def scan_ip(self, ip):
        """Scan a single IP address"""
        try:
            # Get MAC address for the IP
            mac = self.get_mac_address(ip)

            # If scan_all_devices is True, include all devices that respond to ping
            # Otherwise, only include devices with MAC addresses that match valid prefixes
            if self.scan_all_devices:
                if mac and mac != "Unknown":
                    extension = self.get_extension(mac)
                    self.device_found.emit(ip, mac, extension)
            else:
                # Check if MAC address matches any of the valid prefixes from the database
                if self.is_valid_mac(mac):
                    extension = self.get_extension(mac)
                    self.device_found.emit(ip, mac, extension)
        except Exception as e:
            logging.info(f"Error scanning {ip}: {e}")

    def is_valid_mac(self, mac):
        """Check if the MAC address starts with any of the valid prefixes"""
        if mac and mac != "Unknown":
            mac_prefix = mac.upper()[:8]  # Take first 6 characters of the MAC address
            # Check if this prefix matches any valid prefixes in the database
            for brand in self.valid_mac_prefixes:
                brand_mac_prefix = brand[2].upper()[:8]  # Assuming MAC address is the third field in the brand table
                if mac_prefix.startswith(brand_mac_prefix):
                    return True
        return False
    
    def ping(self, ip):
        """Check if an IP address responds to ping"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', '1', ip]
            return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except:
            return False

    def get_mac_address(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
            if platform.system().lower() == 'windows':
                # Windows
                output = subprocess.check_output(f'arp -a {ip}', shell=True).decode('utf-8')
                mac_matches = re.findall(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
                if mac_matches:
                    return mac_matches[0].upper()
            else:
                # Linux/Mac
                output = subprocess.check_output(f'arp -n {ip}', shell=True).decode('utf-8')
                mac_matches = re.findall(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', output)
                if mac_matches:
                    return mac_matches[0].upper()
        except:
            pass
        return "Unknown"
    
    def get_all_brands(self):
        """Retrieve all brands and their MAC address prefixes from the database"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, name, mac_address FROM brands ORDER BY name")
            brands = cursor.fetchall()
            
            conn.close()
            return brands
        except Exception as e:
            logging.info(f"Database error: {e}")
            return []
    
       
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
            logging.info(f"Database error: {e}")
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



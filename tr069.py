import sys
import os
import socket
import threading
import base64
import time
import re
import logging
import ipaddress
import platform
import subprocess
import sqlite3
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (QApplication, QInputDialog, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, 
                            QGroupBox, QFormLayout, QSpinBox, QMessageBox, QCheckBox,
                            QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QComboBox,
                            QTabWidget, QDialog, QProgressBar, QRadioButton, QButtonGroup,
                            QScrollArea, QFrame, QSizePolicy, QDateTimeEdit, QCalendarWidget,
                            QListWidget, QListWidgetItem, QAbstractItemView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QDateTime, QTimer
from PyQt5.QtGui import QCursor, QIcon, QColor

# Suppress all warnings
import warnings
warnings.filterwarnings("ignore")

# Import ctypes for Windows-specific console hiding
import ctypes

# Create a directory for logs that won't show in console
os.makedirs("C:/Auto/Logs", exist_ok=True)
sys.stdout = open("C:/Auto/Logs/stdout.log", "w")


# Configure logging to file instead of console
logging.basicConfig(
    filename="C:/Auto/Logs/stdout.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Aggressively hide console in Windows
if platform.system().lower() == 'windows':
    # Hide console window
    if hasattr(sys, 'frozen'):
        # This will hide the console window if running as a frozen executable
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    # Additional console hiding for Windows
    kernel32 = ctypes.WinDLL('kernel32')
    user32 = ctypes.WinDLL('user32')
    
    # Try to detach from console
    kernel32.FreeConsole()

# Database path
DB_PATH = "C:/Auto/Database/Auto.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Modified subprocess functions to prevent console windows
def silent_run(command, shell=False):
    """Run a command without showing console window"""
    startupinfo = None
    if platform.system().lower() == 'windows':
        # This prevents console window from showing on Windows
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
    
    try:
        return subprocess.run(
            command,
            shell=shell,
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
           
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
        )
    except Exception as e:
        logging.error(f"Error running command {command}: {e}")
        return None

def silent_check_output(command, shell=False):
    """Run a command and get output without showing console window"""
    startupinfo = None
    if platform.system().lower() == 'windows':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
    
    try:
        return subprocess.check_output(
            command,
            shell=shell,
            startupinfo=startupinfo,
          
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
        )
    except Exception as e:
        logging.error(f"Error getting output from command {command}: {e}")
        return b""

class Device:
    def __init__(self, ip, manufacturer="", model="", serial="", firmware=""):
        self.ip = ip
        self.manufacturer = manufacturer
        self.model = model
        self.serial = serial
        self.firmware = firmware
        self.last_seen = datetime.now()
        self.status = "Connected"
        self.device_type = "unknown"
        self.scheduled_upgrade = None
        # New attributes for Update Now feature
        self.upgrade_status = "idle"  # idle, processing, success, failed
        self.upgrade_progress = 0  # 0-100
        self.upgrade_message = ""
    
    def update_last_seen(self):
        self.last_seen = datetime.now()
    
    def set_upgrade_status(self, status, progress=0, message=""):
        """Set upgrade status for Update Now feature"""
        self.upgrade_status = status
        self.upgrade_progress = progress
        self.upgrade_message = message
        if status == "processing":
            self.status = f"Upgrading: {progress}% - {message}"
        elif status == "success":
            self.status = "Upgrade Successful"
        elif status == "failed":
            self.status = f"Upgrade Failed: {message}"
        else:
            self.status = "Connected"
    
    def to_dict(self):
        scheduled_time = ""
        if self.scheduled_upgrade:
            scheduled_time = self.scheduled_upgrade.strftime("%Y-%m-%d %H:%M:%S")
            
        return {
            "ip": self.ip,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial": self.serial,
            "firmware": self.firmware,
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "status": self.status,
            "device_type": self.device_type,
            "scheduled_upgrade": scheduled_time,
            "upgrade_status": self.upgrade_status,
            "upgrade_progress": self.upgrade_progress,
            "upgrade_message": self.upgrade_message
        }

class NetworkScanner(QThread):
    """Thread for scanning network devices"""
    device_found = pyqtSignal(str, str, str)  # IP, MAC, hostname
    scan_complete = pyqtSignal()
    
    def __init__(self, ip_range):
        super().__init__()
        self.ip_range = ip_range
        self.stop_flag = False
        
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
                if self.stop_flag:
                    break
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
            logging.error(f"Scan error: {e}")
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
    
    def scan_ip(self, ip):
        """Scan a single IP address"""
        try:
            # Check if device responds to ping - using silent version
            if not self.ping(ip):
                return
                
            # Get MAC address - using silent version
            mac = self.get_mac_address(ip)
            if mac == "Unknown":
                return
                
            # Get hostname
            hostname = self.get_hostname(ip)
            
            # Check if TR-069 port is open
            tr069_open = self.check_tr069_port(ip)
            
            if tr069_open:
                self.device_found.emit(ip, mac, hostname)
        except Exception as e:
            logging.info(f"Error scanning {ip}: {e}")
    
    def ping(self, ip):
        """Check if an IP address responds to ping - without console window"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', '1', ip]
            
            # Use silent_run instead of subprocess.call
            result = silent_run(command)
            return result and result.returncode == 0
        except:
            return False
    
    def get_mac_address(self, ip):
        """Get MAC address for an IP using ARP - without console window"""
        try:
            if platform.system().lower() == 'windows':
                # Windows - use silent_check_output
                output = silent_check_output(f'arp -a {ip}', shell=True).decode('utf-8')
                mac_matches = re.findall(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
                if mac_matches:
                    return mac_matches[0].upper()
            else:
                # Linux/Mac - use silent_check_output
                output = silent_check_output(f'arp -n {ip}', shell=True).decode('utf-8')
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
    
    def check_tr069_port(self, ip):
        """Check if TR-069 port (7547) is open on the device"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 7547))
            sock.close()
            return result == 0
        except:
            return False

class TR069Server(QThread):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    device_signal = pyqtSignal(dict)
    
    def __init__(self, host, port, username, password, firmware_path, http_port=8080, force_upgrade=True, device_type="auto"):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.firmware_path = firmware_path
        self.http_port = http_port
        self.force_upgrade = force_upgrade
        self.device_type = device_type
        self.running = False
        self.server_socket = None
        self.devices = {}  # Store connected devices
        self.bypass_auth = True  # Bypass authentication for problematic devices
        self.max_line_length = 512  # Maximum line length for responses
        self.scheduled_upgrades = {}  # Store scheduled upgrades {ip: datetime}
        
        # New attributes for Update Now feature
        self.immediate_upgrades = {}  # Store immediate upgrade requests {ip: firmware_path}
        self.upgrade_status_lock = threading.Lock()  # Thread safety for status updates
        
        # Get firmware filename from path
        self.firmware_filename = os.path.basename(firmware_path) if firmware_path else ""
        
        # Get firmware file size
        try:
            self.firmware_size = os.path.getsize(firmware_path) if firmware_path else 0
            if self.firmware_size == 0 and firmware_path:
                self.log(f"WARNING: Firmware file is empty: {firmware_path}")
        except Exception as e:
            self.log(f"Error getting firmware file size: {e}")
            self.firmware_size = 0
        
        # Base64 encode username:password
        self.credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        
        # Track device connection attempts
        self.connection_attempts = {}
        
        # Device-specific configurations
        self.device_configs = {
            "neron": {
                "file_type": "1 Firmware Upgrade Image",
                "max_line_length": 512,
                "force_reboot": True,
                "retry_count": 5,
                "retry_delay": 6
            },
            "yealink": {
                "file_type": "1 Firmware Upgrade Image", 
                "max_line_length": 1024,
                "force_reboot": True,
                "retry_count": 3,
                "retry_delay": 5
            },
            "grandstream": {
                "file_type": "3 Firmware Upgrade Image",
                "max_line_length": 2048,
                "force_reboot": True,
                "retry_count": 3,
                "retry_delay": 5,
                "xml_format": "expanded"  # Grandstream prefers expanded XML
            },
            "fanvil": {
                "file_type": "1 Firmware Upgrade Image",
                "max_line_length": 1024,
                "force_reboot": True,
                "retry_count": 4,
                "retry_delay": 5,
                "xml_format": "compact"  # Fanvil prefers compact XML
            },
            "alcatel": {
                "file_type": "1 Firmware Upgrade Image",
                "max_line_length": 1024,
                "force_reboot": True,
                "retry_count": 3,
                "retry_delay": 6,
                "xml_format": "standard"  # Alcatel uses standard XML format
            },
            "default": {
                "file_type": "1 Firmware Upgrade Image",
                "max_line_length": 1024,
                "force_reboot": True,
                "retry_count": 3,
                "retry_delay": 5,
                "xml_format": "standard"
            }
        }
        
        # Start the scheduler thread
        self.scheduler_thread = threading.Thread(target=self.check_scheduled_upgrades)
        self.scheduler_thread.daemon = True
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_signal.emit(f"[{timestamp}] {message}")
    
    def update_device_upgrade_status(self, device_ip, status, progress=0, message=""):
        """Update device upgrade status for Update Now feature"""
        with self.upgrade_status_lock:
            if device_ip in self.devices:
                self.devices[device_ip].set_upgrade_status(status, progress, message)
                self.device_signal.emit(self.devices[device_ip].to_dict())
    
    def initiate_immediate_upgrade(self, device_ip, firmware_path):
        """Initiate immediate firmware upgrade for Update Now feature"""
        if device_ip not in self.devices:
            self.log(f"Cannot initiate immediate upgrade: Device {device_ip} not found")
            return False
        
        # Update firmware path
        self.firmware_path = firmware_path
        self.firmware_filename = os.path.basename(firmware_path)
        
        # Update firmware size
        try:
            self.firmware_size = os.path.getsize(firmware_path)
        except Exception as e:
            self.log(f"Error getting firmware file size: {e}")
            self.firmware_size = 0
            return False
        
        # Store immediate upgrade request
        self.immediate_upgrades[device_ip] = firmware_path
        
        # Update device status
        self.update_device_upgrade_status(device_ip, "processing", 10, "Initiating upgrade")
        
        # Try to connect to device and send upgrade command
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10.0)
            client_socket.connect((device_ip, self.port))
            
            # Send download command
            self.log(f"Sending immediate Download command to {device_ip}")
            self.update_device_upgrade_status(device_ip, "processing", 20, "Sending download command")
            
            self.send_download_command(client_socket, device_ip, self.devices[device_ip].device_type)
            
            client_socket.close()
            
            self.update_device_upgrade_status(device_ip, "processing", 30, "Download command sent")
            self.log(f"Immediate upgrade initiated for {device_ip}")
            return True
            
        except Exception as e:
            self.log(f"Error initiating immediate upgrade for {device_ip}: {e}")
            self.update_device_upgrade_status(device_ip, "failed", 0, f"Connection failed: {str(e)}")
            # Remove from immediate upgrades
            if device_ip in self.immediate_upgrades:
                del self.immediate_upgrades[device_ip]
            return False
        
    def run(self):
        self.running = True
        self.status_signal.emit("Running")
        
        # Start the scheduler thread
        self.scheduler_thread.start()
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.settimeout(1.0)  # 1 second timeout for graceful shutdown
            self.server_socket.listen(10)
            
            self.log(f"TR-069 Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # Only log if we're still supposed to be running
                        self.log(f"Error accepting connection: {e}")
                    
        except Exception as e:
            self.log(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            self.running = False
            self.status_signal.emit("Stopped")
            self.log("Server stopped")
    
    def stop(self):
        self.running = False
        # Create a connection to ourselves to break the accept() call
        if self.server_socket:
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((self.host, self.port))
            except:
                pass
    
    def check_scheduled_upgrades(self):
        """Check for scheduled upgrades and initiate them when the time comes"""
        while self.running:
            current_time = datetime.now()
            
            # Check each device for scheduled upgrades
            for ip, device in list(self.devices.items()):
                if hasattr(device, 'scheduled_upgrade') and device.scheduled_upgrade:
                    # If the scheduled time has passed, initiate the upgrade
                    if current_time >= device.scheduled_upgrade:
                        self.log(f"Scheduled upgrade time reached for {ip}. Initiating upgrade.")
                        
                        # Create a connection to the device and send upgrade command
                        try:
                            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            client_socket.settimeout(5.0)
                            client_socket.connect((ip, self.port))
                            
                            # Send download command
                            self.log(f"Sending scheduled Download command to {ip}")
                            self.send_download_command(client_socket, ip, device.device_type)
                            
                            # Update device status
                            device.status = "Scheduled Upgrade Initiated"
                            device.scheduled_upgrade = None  # Clear the schedule
                            self.device_signal.emit(device.to_dict())
                            
                            client_socket.close()
                        except Exception as e:
                            self.log(f"Error initiating scheduled upgrade for {ip}: {e}")
            
            # Sleep for a minute before checking again (changed from 10 seconds to 60 seconds)
            time.sleep(60)
    
    def schedule_firmware_upgrade(self, device_ip, schedule_time, firmware_path=None):
        """Schedule a firmware upgrade for a device"""
        if device_ip not in self.devices:
            self.log(f"Cannot schedule upgrade: Device {device_ip} not found")
            return False
        
        # Update firmware path if provided
        if firmware_path:
            self.firmware_path = firmware_path
            self.firmware_filename = os.path.basename(firmware_path)
            
            # Update firmware size
            try:
                self.firmware_size = os.path.getsize(firmware_path)
            except Exception as e:
                self.log(f"Error getting firmware file size: {e}")
                self.firmware_size = 0
        
        # Set the scheduled upgrade time
        self.devices[device_ip].scheduled_upgrade = schedule_time
        self.devices[device_ip].status = f"Upgrade Scheduled for {schedule_time.strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Emit signal to update UI
        self.device_signal.emit(self.devices[device_ip].to_dict())
        
        self.log(f"Firmware upgrade scheduled for {device_ip} at {schedule_time.strftime('%Y-%m-%d %H:%M:%S')}")
        return True
    
    def handle_client(self, client_socket, client_address):
        self.log(f"New connection from {client_address[0]}:{client_address[1]}")
        
        try:
            # Set a timeout to prevent hanging
            client_socket.settimeout(10.0)
            
            # Receive the request
            request_data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                
                # Check if we've received the full HTTP request
                if b"\r\n\r\n" in request_data:
                    # If there's a Content-Length header, make sure we've received the full body
                    header_end = request_data.find(b"\r\n\r\n") + 4
                    headers = request_data[:header_end].decode('utf-8', errors='ignore')
                    
                    # Check for chunked encoding
                    is_chunked = False
                    for line in headers.split("\r\n"):
                        if line.lower().startswith("transfer-encoding:") and "chunked" in line.lower():
                            is_chunked = True
                            break
                    
                    if is_chunked:
                        # For chunked encoding, we need to check for the terminating chunk
                        if b"\r\n0\r\n\r\n" in request_data:
                            break
                    else:
                        # For Content-Length encoding
                        content_length = 0
                        for line in headers.split("\r\n"):
                            if line.lower().startswith("content-length:"):
                                content_length = int(line.split(":", 1)[1].strip())
                                break
                        
                        if len(request_data) - header_end >= content_length:
                            break
            
            if not request_data:
                self.log(f"Empty request from {client_address[0]}:{client_address[1]}")
                return
            
            # Convert to string for easier processing
            request = request_data.decode('utf-8', errors='ignore')
            
            # Log the request (truncated for readability)
            request_log = request.split('\r\n\r\n')[0]
            self.log(f"Request from {client_address[0]}:{client_address[1]}:\n{request_log}")
            
            # Parse headers
            headers = {}
            for line in request.split("\r\n"):
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.lower()] = value
            
            # Detect device type from User-Agent and other headers
            device_type = self.detect_device_type(headers, request)
            
            # Update device config based on detected type
            if device_type in self.device_configs:
                self.max_line_length = self.device_configs[device_type]["max_line_length"]
                self.log(f"Detected device type: {device_type}, max line length: {self.max_line_length}")
            
            # Track connection attempts for this IP
            if client_address[0] not in self.connection_attempts:
                self.connection_attempts[client_address[0]] = 0
            self.connection_attempts[client_address[0]] += 1
            
            # Check if this is the first request without auth
            auth_valid = False
            
            if "authorization" in headers:
                # Check authorization
                auth_header = headers.get("authorization", "")
                if auth_header.startswith("Basic "):
                    received_credentials = auth_header.split(' ')[1]
                    if received_credentials == self.credentials:
                        auth_valid = True
                        self.log(f"Authentication successful from {client_address[0]}:{client_address[1]}")
            
            # If auth is not valid, decide whether to bypass or request auth
            if not auth_valid:
                # If we're bypassing auth or this device has tried multiple times, proceed anyway
                if self.bypass_auth or self.connection_attempts[client_address[0]] >= 2:
                    self.log(f"Bypassing authentication for {client_address[0]} (attempt {self.connection_attempts[client_address[0]]})")
                    auth_valid = True  # Treat as authenticated
                else:
                    self.log(f"No valid Authorization header. Sending 401 Unauthorized to {client_address[0]}:{client_address[1]}")
                    self.send_unauthorized(client_socket)
                    return
            
            # Handle different TR-069 requests
            if "cwmp:Inform" in request:
                # Respond to Inform
                self.log(f"Received Inform request from {client_address[0]}:{client_address[1]}")
                
                # Extract device information
                device_info = self.extract_device_info(request)
                if device_info:
                    self.log(f"Device Info: {device_info}")
                    
                    # Update device list
                    device_ip = client_address[0]
                    if device_ip not in self.devices:
                        # New device
                        device = Device(
                            ip=device_ip,
                            manufacturer=device_info.get("Manufacturer", ""),
                            model=device_info.get("Model", ""),
                            serial=device_info.get("SerialNumber", ""),
                            firmware=device_info.get("FirmwareVersion", "")
                        )
                        device.device_type = device_type
                        self.devices[device_ip] = device
                    else:
                        # Update existing device
                        self.devices[device_ip].manufacturer = device_info.get("Manufacturer", self.devices[device_ip].manufacturer)
                        self.devices[device_ip].model = device_info.get("Model", self.devices[device_ip].model)
                        self.devices[device_ip].serial = device_info.get("SerialNumber", self.devices[device_ip].serial)
                        self.devices[device_ip].firmware = device_info.get("FirmwareVersion", self.devices[device_ip].firmware)
                        self.devices[device_ip].device_type = device_type
                        self.devices[device_ip].update_last_seen()
                        # Only update status if not in upgrade process
                        if self.devices[device_ip].upgrade_status == "idle":
                            self.devices[device_ip].status = "Connected"
                    
                    # Emit signal to update UI
                    self.device_signal.emit(self.devices[device_ip].to_dict())
                
                # Send InformResponse with appropriate line length for the device
                self.send_inform_response(client_socket, device_type)
                
                # Check if we need to send a download command
                device_ip = client_address[0]
                
                # Priority 1: Check for immediate upgrade requests (Update Now feature)
                if device_ip in self.immediate_upgrades:
                    self.log(f"Processing immediate upgrade request for {device_ip}")
                    self.update_device_upgrade_status(device_ip, "processing", 40, "Sending download command")
                    self.send_download_command(client_socket, device_ip, device_type)
                    # Don't remove from immediate_upgrades yet, wait for TransferComplete
                
                # Priority 2: Check for scheduled upgrades
                elif device_ip in self.devices and not any(status in self.devices[device_ip].status for status in ["Downloading", "Upgrading", "Rebooting"]):
                    # Check if this device has a scheduled upgrade that's due
                    current_time = datetime.now()
                    if hasattr(self.devices[device_ip], 'scheduled_upgrade') and self.devices[device_ip].scheduled_upgrade:
                        if current_time >= self.devices[device_ip].scheduled_upgrade:
                            # Send Download command
                            self.log(f"Sending scheduled Download command to {client_address[0]}:{client_address[1]}")
                            self.send_download_command(client_socket, client_address[0], device_type)
                            
                            # Clear the schedule
                            self.devices[device_ip].scheduled_upgrade = None
                
            elif "cwmp:TransferComplete" in request:
                # Respond to TransferComplete
                self.log(f"Firmware download completed on {client_address[0]}:{client_address[1]}")
                device_ip = client_address[0]
                
                # Check if transfer was successful
                if "<FaultCode>0</FaultCode>" in request:
                    self.log(f"Transfer completed successfully on {client_address[0]}")
                    
                    # Update status based on upgrade type
                    if device_ip in self.immediate_upgrades:
                        self.update_device_upgrade_status(device_ip, "processing", 70, "Download complete, installing")
                    elif client_address[0] in self.devices:
                        self.devices[client_address[0]].status = "Transfer Complete - Upgrading"
                        self.device_signal.emit(self.devices[client_address[0]].to_dict())
                    
                    # Send TransferCompleteResponse
                    self.send_transfer_complete_response(client_socket, device_type)
                    
                    # Wait a moment to ensure the device has processed the response
                    time.sleep(1)
                    
                    # Send Reboot command
                    self.log(f"Sending Reboot command to {client_address[0]}:{client_address[1]}")
                    self.send_reboot_command(client_socket, device_type)
                    
                    # Update device status
                    if device_ip in self.immediate_upgrades:
                        self.update_device_upgrade_status(device_ip, "processing", 90, "Rebooting for upgrade")
                    elif client_address[0] in self.devices:
                        self.devices[client_address[0]].status = "Rebooting for Upgrade"
                        self.device_signal.emit(self.devices[client_address[0]].to_dict())
                else:
                    # Extract fault code and message if available
                    fault_code_match = re.search(r"<FaultCode>(\d+)</FaultCode>", request)
                    fault_string_match = re.search(r"<FaultString>(.*?)</FaultString>", request)
                    
                    fault_code = fault_code_match.group(1) if fault_code_match else "Unknown"
                    fault_string = fault_string_match.group(1) if fault_string_match else "Unknown error"
                    
                    self.log(f"Transfer failed on {client_address[0]}: {fault_code} - {fault_string}")
                    
                    # Update status based on upgrade type
                    if device_ip in self.immediate_upgrades:
                        self.update_device_upgrade_status(device_ip, "failed", 0, f"Transfer failed: {fault_string}")
                        # Remove from immediate upgrades
                        del self.immediate_upgrades[device_ip]
                    elif client_address[0] in self.devices:
                        self.devices[client_address[0]].status = f"Transfer Failed: {fault_string}"
                        self.device_signal.emit(self.devices[client_address[0]].to_dict())
                    
                    # Send TransferCompleteResponse
                    self.send_transfer_complete_response(client_socket, device_type)
                
            elif "cwmp:DownloadResponse" in request:
                # Respond to DownloadResponse
                self.log(f"Received DownloadResponse from {client_address[0]}:{client_address[1]}")
                device_ip = client_address[0]
                
                # Check if download was accepted
                status_match = re.search(r"<Status>(\d+)</Status>", request)
                if status_match:
                    status_code = status_match.group(1)
                    if status_code == "0":
                        self.log(f"Download accepted by device {client_address[0]}")
                        
                        # Update status based on upgrade type
                        if device_ip in self.immediate_upgrades:
                            self.update_device_upgrade_status(device_ip, "processing", 50, "Downloading firmware")
                        elif client_address[0] in self.devices:
                            self.devices[client_address[0]].status = "Downloading Firmware"
                            self.device_signal.emit(self.devices[client_address[0]].to_dict())
                    else:
                        # Extract fault string if available
                        start_time_match = re.search(r"<StartTime>(.*?)</StartTime>", request)
                        complete_time_match = re.search(r"<CompleteTime>(.*?)</CompleteTime>", request)
                        
                        start_time = start_time_match.group(1) if start_time_match else "Unknown"
                        complete_time = complete_time_match.group(1) if complete_time_match else "Unknown"
                        
                        self.log(f"Download rejected by device {client_address[0]} with status {status_code}")
                        self.log(f"Start time: {start_time}, Complete time: {complete_time}")
                        
                        # Update status based on upgrade type
                        if device_ip in self.immediate_upgrades:
                            self.update_device_upgrade_status(device_ip, "failed", 0, f"Download rejected: Status {status_code}")
                            # Remove from immediate upgrades
                            del self.immediate_upgrades[device_ip]
                        elif client_address[0] in self.devices:
                            self.devices[client_address[0]].status = f"Download Failed: Status {status_code}"
                            self.device_signal.emit(self.devices[client_address[0]].to_dict())
                
                self.send_empty_response(client_socket)
                
            elif "cwmp:RebootResponse" in request:
                # Respond to RebootResponse
                self.log(f"Received RebootResponse from {client_address[0]}:{client_address[1]}")
                device_ip = client_address[0]
                
                self.send_empty_response(client_socket)
                
                # Update device status and complete upgrade process
                if device_ip in self.immediate_upgrades:
                    # Complete the immediate upgrade
                    self.update_device_upgrade_status(device_ip, "success", 100, "Upgrade completed successfully")
                    # Remove from immediate upgrades
                    del self.immediate_upgrades[device_ip]
                    self.log(f"Immediate upgrade completed successfully for {device_ip}")
                elif client_address[0] in self.devices:
                    self.devices[client_address[0]].status = "Rebooting"
                    self.device_signal.emit(self.devices[client_address[0]].to_dict())
                
            # Handle GetParameterValues request
            elif "cwmp:GetParameterValues" in request:
                self.log(f"Received GetParameterValues from {client_address[0]}:{client_address[1]}")
                self.send_get_parameter_values_response(client_socket, device_type)
                
            # Handle SetParameterValues request
            elif "cwmp:SetParameterValues" in request:
                self.log(f"Received SetParameterValues from {client_address[0]}:{client_address[1]}")
                self.send_set_parameter_values_response(client_socket, device_type)
                
            # Handle GetRPCMethods request
            elif "cwmp:GetRPCMethods" in request:
                self.log(f"Received GetRPCMethods from {client_address[0]}:{client_address[1]}")
                self.send_get_rpc_methods_response(client_socket, device_type)
                
            else:
                # Unknown request - send empty response
                self.log(f"Unknown request from {client_address[0]}:{client_address[1]}")
                self.send_empty_response(client_socket)
                
        except Exception as e:
            self.log(f"Error handling client {client_address[0]}:{client_address[1]}: {e}")
        finally:
            client_socket.close()
    
    def detect_device_type(self, headers, request):
        """Detect device type from headers and request content"""
        # Default device type
        device_type = "default"
        
        # Check User-Agent header
        if "user-agent" in headers:
            user_agent = headers["user-agent"].lower()
            
            # Yealink detection
            if "yealink" in user_agent:
                device_type = "yealink"
            
            # Neron detection
            elif "neron" in user_agent or any(model in user_agent for model in ["502hd", "504hd", "508hd", "510hd"]):
                device_type = "neron"
            
            # Grandstream detection
            elif "grandstream" in user_agent:
                device_type = "grandstream"
            
            # Fanvil detection
            elif "fanvil" in user_agent or "x-lite" in user_agent:
                device_type = "fanvil"
            
            # Alcatel detection
            elif "alcatel" in user_agent or "lucent" in user_agent:
                device_type = "alcatel"
        
        # If not found in User-Agent, try to detect from request body
        if device_type == "default" and request:
            # Look for manufacturer in the request body
            manufacturer_patterns = [
                (r"<Manufacturer>Yealink</Manufacturer>", "yealink"),
                (r"<Manufacturer>Neron</Manufacturer>", "neron"),
                (r"<Manufacturer>Grandstream</Manufacturer>", "grandstream"),
                (r"<Manufacturer>Fanvil</Manufacturer>", "fanvil"),
                (r"<Manufacturer>Alcatel</Manufacturer>", "alcatel"),
                # Additional patterns for different formats
                (r"Yealink", "yealink"),
                (r"Neron", "neron"),
                (r"Grandstream", "grandstream"),
                (r"Fanvil", "fanvil"),
                (r"Alcatel", "alcatel")
            ]
            
            for pattern, detected_type in manufacturer_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    device_type = detected_type
                    break
        
        return device_type
    
    def extract_device_info(self, request):
        """Extract device information from the Inform request"""
        try:
            info = {}
            
            # Extract manufacturer
            if "<Manufacturer>" in request and "</Manufacturer>" in request:
                manufacturer = request.split("<Manufacturer>")[1].split("</Manufacturer>")[0]
                info["Manufacturer"] = manufacturer
            
            # Extract model
            if "<ProductClass>" in request and "</ProductClass>" in request:
                model = request.split("<ProductClass>")[1].split("</ProductClass>")[0]
                info["Model"] = model
            elif "<ModelName>" in request and "</ModelName>" in request:
                model = request.split("<ModelName>")[1].split("</ModelName>")[0]
                info["Model"] = model
            
            # Extract serial number
            if "<SerialNumber>" in request and "</SerialNumber>" in request:
                serial = request.split("<SerialNumber>")[1].split("</SerialNumber>")[0]
                info["SerialNumber"] = serial
            
            # Extract current firmware version - improved extraction to handle different formats
            firmware_version = None
            
            # Try different patterns for firmware version
            patterns = [
                r"<SoftwareVersion>(.*?)</SoftwareVersion>",
                r"<Name>Device\.DeviceInfo\.SoftwareVersion</Name>.*?<Value[^>]*>(.*?)</Value>",
                r"<Name>InternetGatewayDevice\.DeviceInfo\.SoftwareVersion</Name>.*?<Value[^>]*>(.*?)</Value>",
                r"<Name>Device\.DeviceInfo\.FirmwareVersion</Name>.*?<Value[^>]*>(.*?)</Value>",
                r"<Name>InternetGatewayDevice\.DeviceInfo\.FirmwareVersion</Name>.*?<Value[^>]*>(.*?)</Value>"
            ]
            
            for pattern in patterns:
                match = re.search(pattern, request, re.DOTALL)
                if match:
                    firmware_version = match.group(1)
                    break
            
            if firmware_version:
                info["FirmwareVersion"] = firmware_version
            
            return info
        except Exception as e:
            self.log(f"Error extracting device info: {e}")
            return None
    
    def send_unauthorized(self, client_socket):
        """Send 401 Unauthorized response"""
        response = '''HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="TR-069 Provisioning Server"
Content-Length: 0
Connection: close

'''
        client_socket.sendall(response.encode('utf-8'))
    
    def format_xml_for_device(self, xml, device_type):
        """Format XML with appropriate line breaks for device type"""
        if device_type not in self.device_configs:
            device_type = "default"
            
        max_line_length = self.device_configs[device_type]["max_line_length"]
        xml_format = self.device_configs[device_type].get("xml_format", "standard")
        
        # Apply device-specific XML formatting
        if xml_format == "compact":
            # Compact format - minimize whitespace
            xml = re.sub(r'>\s+<', '><', xml)
            xml = re.sub(r'\s+', ' ', xml)
        elif xml_format == "expanded":
            # Expanded format - add more whitespace for readability
            xml = re.sub(r'><', '>\n<', xml)
        
        # Split XML into lines that don't exceed max_line_length
        formatted_lines = []
        current_line = ""
        
        # First, split by existing line breaks
        for line in xml.split("\n"):
            if len(line) <= max_line_length:
                formatted_lines.append(line)
            else:
                # Need to split this line further
                words = line.split()
                for word in words:
                    if len(current_line) + len(word) + 1 <= max_line_length:
                        if current_line:
                            current_line += " " + word
                        else:
                            current_line = word
                    else:
                        formatted_lines.append(current_line)
                        current_line = word
                
                if current_line:
                    formatted_lines.append(current_line)
                    current_line = ""
        
        # Add any remaining content
        if current_line:
            formatted_lines.append(current_line)
            
        return "\n".join(formatted_lines)
    
    def send_inform_response(self, client_socket, device_type):
        """Send InformResponse with appropriate formatting for device type"""
        xml_body = '''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:InformResponse>
         <MaxEnvelopes>1</MaxEnvelopes>
      </cwmp:InformResponse>
   </soapenv:Body>
</soapenv:Envelope>'''
        
        # Format XML for device
        body = self.format_xml_for_device(xml_body, device_type)
        
        # Construct HTTP response with appropriate line breaks
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml; charset=\"utf-8\"",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines)
        client_socket.sendall(response.encode('utf-8'))
    
    def get_file_type_for_device(self, device_ip, device_type):
        """Determine the correct FileType value based on device type"""
        if device_type in self.device_configs:
            return self.device_configs[device_type]["file_type"]
        
        # Fallback to auto-detection based on device info
        if device_ip in self.devices:
            manufacturer = self.devices[device_ip].manufacturer.lower()
            if "yealink" in manufacturer:
                return self.device_configs["yealink"]["file_type"]
            elif "neron" in manufacturer or "502hd" in manufacturer or "504hd" in manufacturer or "508hd" in manufacturer:
                return self.device_configs["neron"]["file_type"]
            elif "grandstream" in manufacturer:
                return self.device_configs["grandstream"]["file_type"]
            elif "fanvil" in manufacturer:
                return self.device_configs["fanvil"]["file_type"]
            elif "alcatel" in manufacturer:
                return self.device_configs["alcatel"]["file_type"]
        
        # Default file type
        return self.device_configs["default"]["file_type"]
    
    def send_download_command(self, client_socket, device_ip, device_type):
        """Send Download command with proper parameters for firmware installation"""
        # Create URL for firmware download
        firmware_url = f"http://{self.host}:{self.http_port}/firmware/{self.firmware_filename}"
        
        # Get the appropriate file type for this device
        file_type = self.get_file_type_for_device(device_ip, device_type)
        
        self.log(f"Using FileType '{file_type}' for device {device_ip}")
        
        # Create a unique command key with timestamp
        command_key = f"firmware_upgrade_{int(time.time())}"
        
        # Check if this is a Yealink device
        is_yealink = device_type == "yealink" or (device_ip in self.devices and "yealink" in self.devices[device_ip].manufacturer.lower())
        
        # Check for Fanvil device
        is_fanvil = device_type == "fanvil" or (device_ip in self.devices and "fanvil" in self.devices[device_ip].manufacturer.lower())
        
        # Check for Alcatel device
        is_alcatel = device_type == "alcatel" or (device_ip in self.devices and "alcatel" in self.devices[device_ip].manufacturer.lower())
        
        # Check for Grandstream device
        is_grandstream = device_type == "grandstream" or (device_ip in self.devices and "grandstream" in self.devices[device_ip].manufacturer.lower())
        
        # Build the SOAP body with appropriate parameters for the device type
        if is_yealink:
            # Yealink-specific format with SuccessURL and FailureURL
            xml_body = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:Download>
         <CommandKey>{command_key}</CommandKey>
         <FileType>{file_type}</FileType>
         <URL>{firmware_url}</URL>
         <Username>{self.username}</Username>
         <Password>{self.password}</Password>
         <FileSize>{self.firmware_size}</FileSize>
         <TargetFileName>{self.firmware_filename}</TargetFileName>
         <DelaySeconds>0</DelaySeconds>
         <SuccessURL></SuccessURL>
         <FailureURL></FailureURL>
      </cwmp:Download>
   </soapenv:Body>
</soapenv:Envelope>'''
        elif is_fanvil:
            # Fanvil-specific format
            xml_body = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:Download>
         <CommandKey>{command_key}</CommandKey>
         <FileType>{file_type}</FileType>
         <URL>{firmware_url}</URL>
         <Username>{self.username}</Username>
         <Password>{self.password}</Password>
         <FileSize>{self.firmware_size}</FileSize>
         <TargetFileName>{self.firmware_filename}</TargetFileName>
         <DelaySeconds>0</DelaySeconds>
      </cwmp:Download>
   </soapenv:Body>
</soapenv:Envelope>'''
        elif is_alcatel:
            # Alcatel-specific format
            xml_body = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:Download>
         <CommandKey>{command_key}</CommandKey>
         <FileType>{file_type}</FileType>
         <URL>{firmware_url}</URL>
         <Username>{self.username}</Username>
         <Password>{self.password}</Password>
         <FileSize>{self.firmware_size}</FileSize>
         <TargetFileName>{self.firmware_filename}</TargetFileName>
         <DelaySeconds>0</DelaySeconds>
      </cwmp:Download>
   </soapenv:Body>
</soapenv:Envelope>'''
        elif is_grandstream:
            # Grandstream-specific format
            xml_body = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:Download>
         <CommandKey>{command_key}</CommandKey>
         <FileType>{file_type}</FileType>
         <URL>{firmware_url}</URL>
         <Username>{self.username}</Username>
         <Password>{self.password}</Password>
         <FileSize>{self.firmware_size}</FileSize>
         <TargetFileName>{self.firmware_filename}</TargetFileName>
         <DelaySeconds>0</DelaySeconds>
      </cwmp:Download>
   </soapenv:Body>
</soapenv:Envelope>'''
        else:
            # Generic format for other devices
            xml_body = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:Download>
         <CommandKey>{command_key}</CommandKey>
         <FileType>{file_type}</FileType>
         <URL>{firmware_url}</URL>
         <Username>{self.username}</Username>
         <Password>{self.password}</Password>
         <FileSize>{self.firmware_size}</FileSize>
         <TargetFileName>{self.firmware_filename}</TargetFileName>
         <DelaySeconds>0</DelaySeconds>
      </cwmp:Download>
   </soapenv:Body>
</soapenv:Envelope>'''
        
        # Format XML for device
        body = self.format_xml_for_device(xml_body, device_type)
        
        # Construct HTTP response with appropriate line breaks
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml; charset=\"utf-8\"",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines)
        client_socket.sendall(response.encode('utf-8'))
    
    def send_transfer_complete_response(self, client_socket, device_type):
        """Send response to TransferComplete"""
        xml_body = '''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:TransferCompleteResponse>
      </cwmp:TransferCompleteResponse>
   </soapenv:Body>
</soapenv:Envelope>'''
        
        # Format XML for device
        body = self.format_xml_for_device(xml_body, device_type)
        
        # Construct HTTP response with appropriate line breaks
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml; charset=\"utf-8\"",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines)
        client_socket.sendall(response.encode('utf-8'))
    
    def send_reboot_command(self, client_socket, device_type):
        """Send Reboot command with proper formatting"""
        # Create a unique command key with timestamp
        command_key = f"reboot_after_upgrade_{int(time.time())}"
        
        xml_body = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:Reboot>
         <CommandKey>{command_key}</CommandKey>
      </cwmp:Reboot>
   </soapenv:Body>
</soapenv:Envelope>'''
        
        # Format XML for device
        body = self.format_xml_for_device(xml_body, device_type)
        
        # Construct HTTP response with appropriate line breaks
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml; charset=\"utf-8\"",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines)
        client_socket.sendall(response.encode('utf-8'))
    
    def send_empty_response(self, client_socket):
        """Send empty 200 OK response"""
        response = '''HTTP/1.1 200 OK
Content-Length: 0
Connection: close

'''
        client_socket.sendall(response.encode('utf-8'))
    
    def send_get_parameter_values_response(self, client_socket, device_type):
        """Send response to GetParameterValues"""
        xml_body = '''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:GetParameterValuesResponse>
         <ParameterList soap:arrayType="cwmp:ParameterValueStruct[1]">
            <ParameterValueStruct>
               <Name>Device.DeviceInfo.SoftwareVersion</Name>
               <Value xsi:type="xsd:string">1.0.0</Value>
            </ParameterValueStruct>
         </ParameterList>
      </cwmp:GetParameterValuesResponse>
   </soapenv:Body>
</soapenv:Envelope>'''
        
        # Format XML for device
        body = self.format_xml_for_device(xml_body, device_type)
        
        # Construct HTTP response with appropriate line breaks
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml; charset=\"utf-8\"",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines)
        client_socket.sendall(response.encode('utf-8'))
    
    def send_set_parameter_values_response(self, client_socket, device_type):
        """Send response to SetParameterValues"""
        xml_body = '''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:SetParameterValuesResponse>
         <Status>0</Status>
      </cwmp:SetParameterValuesResponse>
   </soapenv:Body>
</soapenv:Envelope>'''
        
        # Format XML for device
        body = self.format_xml_for_device(xml_body, device_type)
        
        # Construct HTTP response with appropriate line breaks
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml; charset=\"utf-8\"",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines)
        client_socket.sendall(response.encode('utf-8'))
    
    def send_get_rpc_methods_response(self, client_socket, device_type):
        """Send response to GetRPCMethods"""
        xml_body = '''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
   <soapenv:Header/>
   <soapenv:Body>
      <cwmp:GetRPCMethodsResponse>
         <MethodList soap:arrayType="xsd:string[8]">
            <string>GetRPCMethods</string>
            <string>SetParameterValues</string>
            <string>GetParameterValues</string>
            <string>GetParameterNames</string>
            <string>SetParameterAttributes</string>
            <string>GetParameterAttributes</string>
            <string>Reboot</string>
            <string>Download</string>
         </MethodList>
      </cwmp:GetRPCMethodsResponse>
   </soapenv:Body>
</soapenv:Envelope>'''
        
        # Format XML for device
        body = self.format_xml_for_device(xml_body, device_type)
        
        # Construct HTTP response with appropriate line breaks
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml; charset=\"utf-8\"",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines)
        client_socket.sendall(response.encode('utf-8'))
    
    def force_reboot_device(self, device_ip):
        """Force a device to reboot by sending multiple reboot commands"""
        if device_ip not in self.devices:
            self.log(f"Device {device_ip} not found in device list")
            return False
        
        device_type = self.devices[device_ip].device_type
        retry_count = self.device_configs.get(device_type, self.device_configs["default"])["retry_count"]
        retry_delay = self.device_configs.get(device_type, self.device_configs["default"])["retry_delay"]
        
        self.log(f"Attempting to force reboot device {device_ip} with {retry_count} attempts")
        
        success = False
        for attempt in range(retry_count):
            try:
                # Create a socket connection to the device
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(5.0)
                client_socket.connect((device_ip, self.port))
                
                # Send reboot command
                self.log(f"Sending force reboot command to {device_ip} (attempt {attempt+1}/{retry_count})")
                self.send_reboot_command(client_socket, device_type)
                
                # Update device status
                self.devices[device_ip].status = f"Force Reboot Attempt {attempt+1}/{retry_count}"
                self.device_signal.emit(self.devices[device_ip].to_dict())
                
                client_socket.close()
                success = True
                
                # Wait before next attempt
                time.sleep(retry_delay)
                
            except Exception as e:
                self.log(f"Error sending reboot command to {device_ip} (attempt {attempt+1}): {e}")
                time.sleep(retry_delay)
        
        if success:
            self.devices[device_ip].status = "Force Reboot Initiated"
            self.device_signal.emit(self.devices[device_ip].to_dict())
            
        return success
    
    def reboot_device(self, device_ip):
        """Create a connection to the device and send a reboot command"""
        if device_ip not in self.devices:
            self.log(f"Device {device_ip} not found in device list")
            return False
        
        device_type = self.devices[device_ip].device_type
        
        try:
            # Create a socket connection to the device
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)
            client_socket.connect((device_ip, self.port))
            
            # Send reboot command
            self.log(f"Sending manual reboot command to {device_ip}")
            self.send_reboot_command(client_socket, device_type)
            
            # Update device status
            self.devices[device_ip].status = "Manual Reboot"
            self.device_signal.emit(self.devices[device_ip].to_dict())
            
            client_socket.close()
            return True
            
        except Exception as e:
            self.log(f"Error sending reboot command to {device_ip}: {e}")
            
            # Try force reboot as fallback
            self.log(f"Attempting force reboot for {device_ip}")
            return self.force_reboot_device(device_ip)
    
    def bulk_upgrade_devices(self, device_ips, firmware_path=None, schedule_time=None):
        """Upgrade multiple devices with the same firmware"""
        if not device_ips:
            self.log("No devices selected for bulk upgrade")
            return False
        
        # Update firmware path if provided
        if firmware_path:
            self.firmware_path = firmware_path
            self.firmware_filename = os.path.basename(firmware_path)
            
            # Update firmware size
            try:
                self.firmware_size = os.path.getsize(firmware_path)
            except Exception as e:
                self.log(f"Error getting firmware file size: {e}")
                self.firmware_size = 0
        
        success_count = 0
        for device_ip in device_ips:
            if device_ip not in self.devices:
                self.log(f"Device {device_ip} not found in device list")
                continue
            
            if schedule_time:
                # Schedule the upgrade
                if self.schedule_firmware_upgrade(device_ip, schedule_time):
                    success_count += 1
            else:
                # Immediate upgrade
                try:
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.settimeout(5.0)
                    client_socket.connect((device_ip, self.port))
                    
                    # Send download command
                    self.log(f"Sending Download command to {device_ip} for bulk upgrade")
                    self.send_download_command(client_socket, device_ip, self.devices[device_ip].device_type)
                    
                    # Update device status
                    self.devices[device_ip].status = "Bulk Upgrade Initiated"
                    self.device_signal.emit(self.devices[device_ip].to_dict())
                    
                    client_socket.close()
                    success_count += 1
                except Exception as e:
                    self.log(f"Error initiating bulk upgrade for {device_ip}: {e}")
        
        self.log(f"Bulk upgrade initiated for {success_count} out of {len(device_ips)} devices")
        return success_count > 0


class FirmwareServer(QThread):
    log_signal = pyqtSignal(str)
    
    def __init__(self, host, port, firmware_path):
        super().__init__()
        self.host = host
        self.port = port
        self.firmware_path = firmware_path
        self.running = False
        self.server_socket = None
    
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_signal.emit(f"[{timestamp}] {message}")
    
    def run(self):
        self.running = True
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.settimeout(1.0)
            self.server_socket.listen(10)
            
            self.log(f"Firmware HTTP Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log(f"Firmware server error: {e}")
        
        except Exception as e:
            self.log(f"Firmware server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            self.running = False
            self.log("Firmware HTTP Server stopped")
    
    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((self.host, self.port))
            except:
                pass
    
    def handle_client(self, client_socket, client_address):
        try:
            # Set a timeout to prevent hanging
            client_socket.settimeout(60.0)  # Increased timeout for large firmware files
            
            # Receive the request
            request_data = b""
            while len(request_data) < 8192:  # Increased buffer size
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                if b"\r\n\r\n" in request_data:
                    break
            
            request = request_data.decode('utf-8', errors='ignore')
            
            if not request:
                return
            
            # Check if this is a firmware request
            if "GET /firmware/" in request:
                self.log(f"Firmware download request from {client_address[0]}:{client_address[1]}")
                self.send_firmware(client_socket, client_address)
            else:
                # Unknown request
                self.send_not_found(client_socket)
        
        except Exception as e:
            self.log(f"Error handling firmware request from {client_address[0]}:{client_address[1]}: {e}")
        finally:
            client_socket.close()
    
    def send_firmware(self, client_socket, client_address):
        """Send the firmware file"""
        try:
            # Check if firmware file exists
            if not os.path.exists(self.firmware_path):
                self.log(f"Firmware file not found: {self.firmware_path}")
                self.send_not_found(client_socket)
                return
            
            # Get file size
            file_size = os.path.getsize(self.firmware_path)
            
            if file_size == 0:
                self.log(f"ERROR: Firmware file is empty: {self.firmware_path}")
                self.send_not_found(client_socket)
                return
            
            # Log firmware details
            self.log(f"Sending firmware file: {self.firmware_path}")
            self.log(f"Firmware file size: {file_size} bytes")
            
            # Send HTTP headers with shorter lines
            headers = [
                "HTTP/1.1 200 OK",
                "Content-Type: application/octet-stream",
                f"Content-Length: {file_size}",
                f"Content-Disposition: attachment; filename=\"{os.path.basename(self.firmware_path)}\"",
                "Connection: close",
                "",
                ""
            ]
            
            client_socket.sendall("\r\n".join(headers).encode('utf-8'))
            
            # Send file in smaller chunks for better compatibility
            bytes_sent = 0
            with open(self.firmware_path, 'rb') as f:
                chunk = f.read(4096)  # Smaller chunk size
                while chunk:
                    client_socket.sendall(chunk)
                    bytes_sent += len(chunk)
                    chunk = f.read(4096)
            
            self.log(f"Firmware file sent successfully to {client_address[0]}:{client_address[1]} ({bytes_sent} bytes)")
        
        except Exception as e:
            self.log(f"Error sending firmware to {client_address[0]}:{client_address[1]}: {e}")
    
    def send_not_found(self, client_socket):
        """Send 404 Not Found response"""
        response = '''HTTP/1.1 404 Not Found
Content-Type: text/html
Content-Length: 162
Connection: close

<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested file was not found on this server.</p>
</body>
</html>'''
        
        client_socket.sendall(response.encode('utf-8'))


class UpdateNowDialog(QDialog):
    """Dialog for immediate firmware upgrade (Update Now feature)"""
    def __init__(self, parent=None, device_ip=None, device_info=None):
        super().__init__(parent)
        self.device_ip = device_ip
        self.device_info = device_info
        self.firmware_path = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Update Firmware Now")
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        # Device info
        if self.device_info:
            info_group = QGroupBox("Device Information")
            info_layout = QFormLayout()
            
            info_layout.addRow("IP Address:", QLabel(self.device_ip))
            info_layout.addRow("Manufacturer:", QLabel(self.device_info.get("manufacturer", "")))
            info_layout.addRow("Model:", QLabel(self.device_info.get("model", "")))
            info_layout.addRow("Serial Number:", QLabel(self.device_info.get("serial", "")))
            info_layout.addRow("Current Firmware:", QLabel(self.device_info.get("firmware", "")))
            
            info_group.setLayout(info_layout)
            layout.addWidget(info_group)
        
        # Firmware selection
        firmware_group = QGroupBox("Firmware Selection")
        firmware_layout = QVBoxLayout()
        
        # Get firmware from database
        self.firmware_combo = QComboBox()
        self.load_firmware_from_db()
        firmware_layout.addWidget(self.firmware_combo)
        
        firmware_group.setLayout(firmware_layout)
        layout.addWidget(firmware_group)
        
        # Warning message
        warning_group = QGroupBox("Important Notice")
        warning_layout = QVBoxLayout()
        
        warning_label = QLabel("⚠️ This will immediately start the firmware upgrade process.\n"
                              "The device will download and install the firmware, then reboot.\n"
                              "Do not power off the device during this process.")
        warning_label.setStyleSheet("color: #d63031; font-weight: bold;")
        warning_layout.addWidget(warning_label)
        
        warning_group.setLayout(warning_layout)
        layout.addWidget(warning_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.update_button = QPushButton("Update Now")
        self.update_button.setStyleSheet("QPushButton { background-color: #00b894; color: white; font-weight: bold; }")
        self.update_button.clicked.connect(self.accept)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.update_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_firmware_from_db(self):
        """Load firmware files from database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Query firmware table
            cursor.execute("SELECT id, filename, path, version FROM firmware ORDER BY id DESC")
            firmwares = cursor.fetchall()
            
            conn.close()
            
            # Add to combo box
            for firmware in firmwares:
                firmware_id, filename, path, version = firmware
                self.firmware_combo.addItem(f"{filename} (v{version})", path)
            
        except Exception as e:
            logging.info(f"Error loading firmware from database: {e}")
            # Add a default item
            self.firmware_combo.addItem("No firmware files found", "")
    
    def get_firmware_path(self):
        """Get selected firmware path"""
        return self.firmware_combo.currentData()


class BulkUpgradeDialog(QDialog):
    def __init__(self, parent=None, device_ips=None):
        super().__init__(parent)
        self.device_ips = device_ips or []
        self.firmware_path = None
        self.scheduled_time = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Bulk Firmware Upgrade")
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout()
        
        # Selected devices
        devices_group = QGroupBox(f"Selected Devices ({len(self.device_ips)})")
        devices_layout = QVBoxLayout()
        
        # Show list of selected devices
        self.devices_list = QListWidget()
        for ip in self.device_ips:
            self.devices_list.addItem(ip)
        devices_layout.addWidget(self.devices_list)
        
        devices_group.setLayout(devices_layout)
        layout.addWidget(devices_group)
        
        # Firmware selection
        firmware_group = QGroupBox("Firmware Selection")
        firmware_layout = QVBoxLayout()
        
        # Get firmware from database
        self.firmware_combo = QComboBox()
        self.load_firmware_from_db()
        firmware_layout.addWidget(self.firmware_combo)
        
        firmware_group.setLayout(firmware_layout)
        layout.addWidget(firmware_group)
        
        # Schedule time
        schedule_group = QGroupBox("Schedule Time")
        schedule_layout = QVBoxLayout()
        
        # Immediate or scheduled radio buttons
        self.immediate_radio = QRadioButton("Upgrade Immediately")
        self.immediate_radio.setChecked(True)
        self.scheduled_radio = QRadioButton("Schedule Upgrade")
        
        schedule_layout.addWidget(self.immediate_radio)
        schedule_layout.addWidget(self.scheduled_radio)
        
        # Date and time picker
        self.datetime_picker = QDateTimeEdit(QDateTime.currentDateTime().addSecs(300))  # Default to 5 minutes from now
        self.datetime_picker.setCalendarPopup(True)
        self.datetime_picker.setMinimumDateTime(QDateTime.currentDateTime())
        self.datetime_picker.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.datetime_picker.setEnabled(False)
        schedule_layout.addWidget(self.datetime_picker)
        
        # Connect radio buttons to enable/disable datetime picker
        self.scheduled_radio.toggled.connect(self.datetime_picker.setEnabled)
        
        schedule_group.setLayout(schedule_layout)
        layout.addWidget(schedule_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.upgrade_button = QPushButton("Start Upgrade")
        self.upgrade_button.clicked.connect(self.accept)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.upgrade_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_firmware_from_db(self):
        """Load firmware files from database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Query firmware table
            cursor.execute("SELECT id, filename, path, version FROM firmware ORDER BY id DESC")
            firmwares = cursor.fetchall()
            
            conn.close()
            
            # Add to combo box
            for firmware in firmwares:
                firmware_id, filename, path, version = firmware
                self.firmware_combo.addItem(f"{filename} (v{version})", path)
            
        except Exception as e:
            logging.info(f"Error loading firmware from database: {e}")
            # Add a default item
            self.firmware_combo.addItem("No firmware files found", "")
    
    def get_firmware_path(self):
        """Get selected firmware path"""
        return self.firmware_combo.currentData()
    
    def get_scheduled_time(self):
        """Get scheduled time if scheduled, otherwise None for immediate"""
        if self.scheduled_radio.isChecked():
            return self.datetime_picker.dateTime().toPyDateTime()
        return None


class ScheduleUpgradeDialog(QDialog):
    def __init__(self, parent=None, device_ip=None, device_info=None):
        super().__init__(parent)
        self.device_ip = device_ip
        self.device_info = device_info
        self.firmware_path = None
        self.scheduled_time = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Schedule Firmware Upgrade")
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        # Device info
        if self.device_info:
            info_group = QGroupBox("Device Information")
            info_layout = QFormLayout()
            
            info_layout.addRow("IP Address:", QLabel(self.device_ip))
            info_layout.addRow("Manufacturer:", QLabel(self.device_info.get("manufacturer", "")))
            info_layout.addRow("Model:", QLabel(self.device_info.get("model", "")))
            info_layout.addRow("Serial Number:", QLabel(self.device_info.get("serial", "")))
            info_layout.addRow("Current Firmware:", QLabel(self.device_info.get("firmware", "")))
            
            info_group.setLayout(info_layout)
            layout.addWidget(info_group)
        
        # Firmware selection
        firmware_group = QGroupBox("Firmware Selection")
        firmware_layout = QVBoxLayout()
        
        # Get firmware from database
        self.firmware_combo = QComboBox()
        self.load_firmware_from_db()
        firmware_layout.addWidget(self.firmware_combo)
        
        firmware_group.setLayout(firmware_layout)
        layout.addWidget(firmware_group)
        
        # Schedule time
        schedule_group = QGroupBox("Schedule Time")
        schedule_layout = QVBoxLayout()
        
        # Date and time picker
        self.datetime_picker = QDateTimeEdit(QDateTime.currentDateTime().addSecs(300))  # Default to 5 minutes from now
        self.datetime_picker.setCalendarPopup(True)
        self.datetime_picker.setMinimumDateTime(QDateTime.currentDateTime())
        self.datetime_picker.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        schedule_layout.addWidget(self.datetime_picker)
        
        # Add a label with instructions
        schedule_info_label = QLabel("Select when the firmware upgrade should be performed.")
        schedule_layout.addWidget(schedule_info_label)
        
        schedule_group.setLayout(schedule_layout)
        layout.addWidget(schedule_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.schedule_button = QPushButton("Schedule Upgrade")
        self.schedule_button.clicked.connect(self.accept)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.schedule_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_firmware_from_db(self):
        """Load firmware files from database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Query firmware table
            cursor.execute("SELECT id, filename, path, version FROM firmware ORDER BY id DESC")
            firmwares = cursor.fetchall()
            
            conn.close()
            
            # Add to combo box
            for firmware in firmwares:
                firmware_id, filename, path, version = firmware
                self.firmware_combo.addItem(f"{filename} (v{version})", path)
            
        except Exception as e:
            logging.info(f"Error loading firmware from database: {e}")
            # Add a default item
            self.firmware_combo.addItem("No firmware files found", "")
    
    def get_firmware_path(self):
        """Get selected firmware path"""
        return self.firmware_combo.currentData()
    
    def get_scheduled_time(self):
        return self.datetime_picker.dateTime().toPyDateTime()


class FirmwareManager:
    def __init__(self):
        self.firmwares = []  # List of firmware files
        self.load_firmware_from_db()
    
    def load_firmware_from_db(self):
        """Load firmware files from database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check if firmware table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='firmware'")
            if not cursor.fetchone():
                # Create firmware table
                cursor.execute('''
                CREATE TABLE firmware (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    path TEXT,
                    size INTEGER,
                    version TEXT,
                    target_device_type TEXT,
                    description TEXT,
                    date_added TEXT
                )
                ''')
                conn.commit()
            
            # Query firmware table
            cursor.execute("SELECT * FROM firmware")
            db_firmwares = cursor.fetchall()
            
            conn.close()
            
            # Convert to list of dictionaries
            for firmware in db_firmwares:
                firmware_id, filename, path, size, version, target_device_type, description, date_added = firmware
                self.firmwares.append({
                    "id": firmware_id,
                    "filename": filename,
                    "path": path,
                    "size": size,
                    "version": version,
                    "target_device_type": target_device_type,
                    "description": description,
                    "date_added": date_added
                })
            
        except Exception as e:
            logging.info(f"Error loading firmware from database: {e}")
    
    def add_firmware(self, path, target_device_type=None, version=None, description=None):
        """Add a firmware file to the manager"""
        if not os.path.exists(path):
            return False
        
        file_size = os.path.getsize(path)
        file_name = os.path.basename(path)
        
        # Extract version from filename if not provided
        if not version:
            # Try to extract version from filename (common patterns)
            version_match = re.search(r'v?(\d+\.\d+\.\d+)', file_name)
            if version_match:
                version = version_match.group(1)
            else:
                version = "Unknown"
        
        # Add to database
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Insert firmware
            cursor.execute('''
            INSERT INTO firmware (filename, path, size, version, target_device_type, description, date_added)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (file_name, path, file_size, version, target_device_type, description, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            
            firmware_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Add to memory
            firmware = {
                "id": firmware_id,
                "path": path,
                "filename": file_name,
                "size": file_size,
                "target_device_type": target_device_type,
                "version": version,
                "description": description,
                "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.firmwares.append(firmware)
            return True
            
        except Exception as e:
            logging.info(f"Error adding firmware to database: {e}")
            return False
    
    def remove_firmware(self, index):
        """Remove a firmware file from the manager"""
        if 0 <= index < len(self.firmwares):
            try:
                firmware_id = self.firmwares[index]["id"]
                
                # Remove from database
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM firmware WHERE id = ?", (firmware_id,))
                conn.commit()
                conn.close()
                
                # Remove from memory
                del self.firmwares[index]
                return True
                
            except Exception as e:
                logging.info(f"Error removing firmware from database: {e}")
                return False
        return False
    
    def get_firmwares(self):
        """Get all firmware files"""
        return self.firmwares
    
    def get_firmware_by_index(self, index):
        """Get firmware by index"""
        if 0 <= index < len(self.firmwares):
            return self.firmwares[index]
        return None
    
    def find_matching_firmware(self, device_info):
        """Find firmware that matches the device"""
        if not device_info:
            return None
        
        device_type = device_info.get("device_type", "").lower()
        manufacturer = device_info.get("manufacturer", "").lower()
        model = device_info.get("model", "").lower()
        
        # First try to find exact match by device type
        for firmware in self.firmwares:
            target = firmware.get("target_device_type", "").lower()
            if target and (target == device_type or 
                          (manufacturer and target in manufacturer) or 
                          (model and target in model)):
                return firmware
        
        # If no exact match, try to find by filename containing model or manufacturer
        for firmware in self.firmwares:
            filename = firmware.get("filename", "").lower()
            if ((manufacturer and manufacturer in filename) or 
                (model and model in filename)):
                return firmware
        
        return None


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.tr069_server = None
        self.firmware_server = None
        self.firmware_manager = FirmwareManager()
        self.network_scanner = None
        
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("TR-069 Firmware Upgrade Tool")
        self.setMinimumSize(900, 700)
        
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        
        self.setCentralWidget(main_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Create tabs
        self.devices_tab = QWidget()
        self.firmwares_tab = QWidget()
        self.server_settings_tab = QWidget()
        self.server_logs_tab = QWidget()
        
        # Add tabs to widget
        self.tabs.addTab(self.devices_tab, "Devices")
        self.tabs.addTab(self.firmwares_tab, "Firmwares")
        self.tabs.addTab(self.server_settings_tab, "Server Settings")
        self.tabs.addTab(self.server_logs_tab, "Server Logs")
        
        # Setup each tab
        self.setup_devices_tab()
        self.setup_firmwares_tab()
        self.setup_server_settings_tab()
        self.setup_server_logs_tab()
        
        # Add tabs to main layout
        main_layout.addWidget(self.tabs)
        
        # Status bar
        # self.statusBar().showMessage("Ready")
        
        # Add initial log message
        self.log("TR-069 Firmware Upgrade Tool started")
        self.log("Please configure server settings and add firmware files")
    
    def setup_devices_tab(self):
        """Setup the Devices tab"""
        layout = QVBoxLayout()
        
        # Search and scan controls
        scan_layout = QHBoxLayout()
        
        # IP Address input
        scan_layout.addWidget(QLabel("IP Range:"))
        self.ip_scan_input = QLineEdit()
        self.ip_scan_input.setText(self.get_local_ip() + "/24")
        scan_layout.addWidget(self.ip_scan_input)
        
        # Scan button
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self.scan_network)
        scan_layout.addWidget(self.scan_button)
        
        # View logs button
        self.view_logs_button = QPushButton("View Logs")
        self.view_logs_button.clicked.connect(lambda: self.tabs.setCurrentIndex(3))  # Switch to logs tab
        scan_layout.addWidget(self.view_logs_button)
        
        layout.addLayout(scan_layout)
        
        # Status label for scan results
        self.scan_status_label = QLabel("Ready to scan")
        layout.addWidget(self.scan_status_label)
        
        # Device actions
        action_layout = QHBoxLayout()
        
        # Search field
        action_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter results...")
        self.search_input.textChanged.connect(self.filter_devices)
        action_layout.addWidget(self.search_input)
        
        # Bulk upgrade button
        self.bulk_upgrade_button = QPushButton("Bulk Upgrade")
        self.bulk_upgrade_button.clicked.connect(self.show_bulk_upgrade_dialog)
        action_layout.addWidget(self.bulk_upgrade_button)
        
        layout.addLayout(action_layout)
        
        # Device table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(8)  # Added one more column for Update Now
        self.device_table.setHorizontalHeaderLabels(["", "S.N.", "IP ADDRESS", "MAC ADDRESS", "MANUFACTURER", "LAST UPDATED", "STATUS", "ACTION"])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.setSelectionMode(QTableWidget.MultiSelection)  # Allow multiple selection
        self.device_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self.show_device_context_menu)
        
        layout.addWidget(self.device_table)
        
        self.devices_tab.setLayout(layout)
    
    def setup_firmwares_tab(self):
        """Setup the Firmwares tab"""
        layout = QVBoxLayout()
        
        # Firmware actions
        action_layout = QHBoxLayout()
        
        # Add firmware button
        self.add_firmware_button = QPushButton("Add Firmware")
        self.add_firmware_button.clicked.connect(self.add_firmware)
        action_layout.addWidget(self.add_firmware_button)
        
        # Remove firmware button
        self.remove_firmware_button = QPushButton("Remove Firmware")
        self.remove_firmware_button.clicked.connect(self.remove_firmware)
        action_layout.addWidget(self.remove_firmware_button)
        
        layout.addLayout(action_layout)
        
        # Firmware table
        self.firmware_table = QTableWidget()
        self.firmware_table.setColumnCount(6)
        self.firmware_table.setHorizontalHeaderLabels(["Filename", "Version", "Size", "Target Device", "Description", "Date Added"])
        self.firmware_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.firmware_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.firmware_table.setSelectionMode(QTableWidget.SingleSelection)
        
        layout.addWidget(self.firmware_table)
        
        self.firmwares_tab.setLayout(layout)
        
        # Update firmware table
        self.update_firmware_table()
    
    def setup_server_settings_tab(self):
        """Setup the Server Settings tab"""
        layout = QVBoxLayout()
        
        # Server settings group
        settings_group = QGroupBox("Server Configuration")
        settings_layout = QFormLayout()
        
        # IP Address
        self.ip_input = QLineEdit()
        self.ip_input.setText(self.get_local_ip())
        settings_layout.addRow("IP Address:", self.ip_input)
        
        # TR-069 Port
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(7547)
        settings_layout.addRow("TR-069 Port:", self.port_input)
        
        # HTTP Port
        self.http_port_input = QSpinBox()
        self.http_port_input.setRange(1, 65535)
        self.http_port_input.setValue(8080)
        settings_layout.addRow("HTTP Port:", self.http_port_input)
        
        # Username
        self.username_input = QLineEdit()
        self.username_input.setText("admin")
        settings_layout.addRow("Username:", self.username_input)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setText("admin")
        settings_layout.addRow("Password:", self.password_input)
        
        # Device Type
        self.device_type_combo = QComboBox()
        self.device_type_combo.addItem("Auto Detect", "auto")
        self.device_type_combo.addItem("Yealink", "yealink")
        self.device_type_combo.addItem("Neron", "neron")
        self.device_type_combo.addItem("Grandstream", "grandstream")
        self.device_type_combo.addItem("Fanvil", "fanvil")
        self.device_type_combo.addItem("Alcatel", "alcatel")
        settings_layout.addRow("Device Type:", self.device_type_combo)
        
        # Force upgrade checkbox
        self.force_upgrade_checkbox = QCheckBox("Force Upgrade")
        self.force_upgrade_checkbox.setChecked(True)
        settings_layout.addRow("", self.force_upgrade_checkbox)
        
        # Bypass authentication checkbox
        self.bypass_auth_checkbox = QCheckBox("Bypass Authentication")
        self.bypass_auth_checkbox.setChecked(True)
        self.bypass_auth_checkbox.setToolTip("Bypass authentication for devices that don't properly authenticate")
        settings_layout.addRow("", self.bypass_auth_checkbox)
        
        # Short response lines checkbox
        self.short_lines_checkbox = QCheckBox("Use Short Response Lines")
        self.short_lines_checkbox.setChecked(True)
        self.short_lines_checkbox.setToolTip("Format responses with shorter lines for better device compatibility")
        settings_layout.addRow("", self.short_lines_checkbox)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Server control group
        control_group = QGroupBox("Server Control")
        control_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.start_server)
        self.stop_button = QPushButton("Stop Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)
        
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Status label
        self.status_label = QLabel("Status: Stopped")
        layout.addWidget(self.status_label)
        
        # Add spacer to push everything to the top
        layout.addStretch()
        
        self.server_settings_tab.setLayout(layout)
    
    def setup_server_logs_tab(self):
        """Setup the Server Logs tab"""
        layout = QVBoxLayout()
        
        # Log controls
        log_controls = QHBoxLayout()
        
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        log_controls.addWidget(self.clear_logs_button)
        
        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.clicked.connect(self.save_logs)
        log_controls.addWidget(self.save_logs_button)
        
        log_controls.addStretch()
        
        layout.addLayout(log_controls)
        
        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        self.server_logs_tab.setLayout(layout)
    
    def get_local_ip(self):
        """Get the local IP address of the machine"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def log(self, message):
        """Add a message to the log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        # Scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def clear_logs(self):
        """Clear the log text area"""
        self.log_text.clear()
        self.log("Logs cleared")
    
    def save_logs(self):
        """Save logs to a file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Logs",
            f"tr069_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.log_text.toPlainText())
                self.log(f"Logs saved to {file_path}")
            except Exception as e:
                self.log(f"Error saving logs: {e}")
                QMessageBox.warning(self, "Save Error", f"Error saving logs: {e}")
    
    def scan_network(self):
        """Scan the network for TR-069 devices"""
        # Get IP range from input
        ip_range = self.ip_scan_input.text().strip()
        if not ip_range:
            QMessageBox.warning(self, "Input Error", "Please enter a valid IP range")
            return
        
        # Update UI
        self.scan_status_label.setText("Scanning network...")
        self.scan_button.setEnabled(False)
        self.device_table.setRowCount(0)
        QApplication.processEvents()  # Update UI
        
        # Start scanner thread
        self.network_scanner = NetworkScanner(ip_range)
        self.network_scanner.device_found.connect(self.add_device)
        self.network_scanner.scan_complete.connect(self.scan_complete)
        self.network_scanner.start()
        
        self.log(f"Network scan started for range: {ip_range}")
    
    def scan_complete(self):
        """Handle scan completion"""
        self.scan_button.setEnabled(True)
        self.scan_status_label.setText(f"Scan complete. Found {self.device_table.rowCount()} TR-069 devices.")
        self.log(f"Network scan completed. Found {self.device_table.rowCount()} TR-069 devices.")
    
    def add_device(self, ip, mac, hostname):
        """Add a device to the table"""
        # Get current timestamp for last updated
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get manufacturer from hostname or set to Unknown
        manufacturer = "Unknown"
        if "yealink" in hostname.lower():
            manufacturer = "Yealink"
        elif "neron" in hostname.lower() or "502hd" in hostname.lower() or "504hd" in hostname.lower():
            manufacturer = "Neron"
        elif "grandstream" in hostname.lower():
            manufacturer = "Grandstream"
        elif "fanvil" in hostname.lower():
            manufacturer = "Fanvil"
        elif "alcatel" in hostname.lower():
            manufacturer = "Alcatel"
        
        # Add to table
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        # Add checkbox for selection
        checkbox = QTableWidgetItem()
        checkbox.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        checkbox.setCheckState(Qt.Unchecked)
        self.device_table.setItem(row, 0, checkbox)
        
        # Add data to table
        self.device_table.setItem(row, 1, QTableWidgetItem(str(row + 1)))
        self.device_table.setItem(row, 2, QTableWidgetItem(ip))
        self.device_table.setItem(row, 3, QTableWidgetItem(mac))
        self.device_table.setItem(row, 4, QTableWidgetItem(manufacturer))
        self.device_table.setItem(row, 5, QTableWidgetItem(current_time))
        self.device_table.setItem(row, 6, QTableWidgetItem("Connected"))  # Status column
        
        # Add action buttons container
        action_widget = QWidget()
        action_layout = QHBoxLayout()
        action_layout.setContentsMargins(2, 2, 2, 2)
        action_layout.setSpacing(2)
        
        # Update Now button (new feature)
        update_now_button = QPushButton("Update Now")
        update_now_button.setStyleSheet("QPushButton { background-color: #00b894; color: white; font-size: 10px; padding: 2px 4px; }")
        update_now_button.clicked.connect(lambda checked, ip=ip: self.show_update_now_dialog(ip))
        action_layout.addWidget(update_now_button)
        
        # Schedule button
        schedule_button = QPushButton("Schedule")
        schedule_button.setStyleSheet("QPushButton { background-color: #0984e3; color: white; font-size: 10px; padding: 2px 4px; }")
        schedule_button.clicked.connect(lambda checked, ip=ip: self.show_schedule_dialog(ip))
        action_layout.addWidget(schedule_button)
        
        action_widget.setLayout(action_layout)
        self.device_table.setCellWidget(row, 7, action_widget)
        
        self.log(f"Found TR-069 device: {ip} ({mac}) - {manufacturer}")
    
    def show_update_now_dialog(self, device_ip):
        """Show Update Now dialog for immediate firmware upgrade"""
        # Get device info from table or server
        device_info = {
            "ip": device_ip,
            "manufacturer": "Unknown",
            "model": "Unknown",
            "serial": "Unknown",
            "firmware": "Unknown"
        }
        
        # Try to get manufacturer from the table
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 2).text() == device_ip:
                device_info["manufacturer"] = self.device_table.item(row, 4).text()
                break
        
        # Try to get more info from server if available
        if self.tr069_server and device_ip in self.tr069_server.devices:
            server_device = self.tr069_server.devices[device_ip]
            device_info.update({
                "manufacturer": server_device.manufacturer or device_info["manufacturer"],
                "model": server_device.model or device_info["model"],
                "serial": server_device.serial or device_info["serial"],
                "firmware": server_device.firmware or device_info["firmware"]
            })
        
        dialog = UpdateNowDialog(self, device_ip, device_info)
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            firmware_path = dialog.get_firmware_path()
            
            if not firmware_path:
                QMessageBox.warning(self, "No Firmware Selected", "Please select a firmware file for the upgrade.")
                return
            
            # Check if server is running
            if not self.tr069_server or not self.tr069_server.isRunning():
                QMessageBox.warning(self, "Server Not Running", "TR-069 server is not running. Please start the server to perform upgrades.")
                return
            
            # Initiate immediate upgrade
            success = self.tr069_server.initiate_immediate_upgrade(device_ip, firmware_path)
            
            if success:
                QMessageBox.information(self, "Update Initiated", 
                                       f"Firmware update initiated for device {device_ip}.\n"
                                       f"You can monitor the progress in the device status.")
                self.log(f"Immediate firmware update initiated for {device_ip}")
            else:
                QMessageBox.warning(self, "Update Failed", 
                                   f"Failed to initiate firmware update for device {device_ip}.\n"
                                   f"Please check the logs for more details.")
    
    def filter_devices(self):
        """Filter the device table based on search text"""
        search_text = self.search_input.text().lower()
        
        for row in range(self.device_table.rowCount()):
            match = False
            
            # Check all columns except the first (checkbox) and last (action button)
            for col in range(1, 7):
                item = self.device_table.item(row, col)
                if item and search_text in item.text().lower():
                    match = True
                    break
            
            self.device_table.setRowHidden(row, not match)
    
    def show_device_context_menu(self, position):
        """Show context menu for device table"""
        menu = QMenu()
        
        # Get selected row
        selected_rows = self.device_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        ip = self.device_table.item(row, 2).text()
        
        # Add menu actions
        update_now_action = menu.addAction("Update Now")
        schedule_action = menu.addAction("Schedule Firmware Upgrade")
        reboot_action = menu.addAction("Reboot Device")
        check_tr069_action = menu.addAction("Check TR-069 Status")
        
        # Show menu and handle selection
        action = menu.exec_(self.device_table.mapToGlobal(position))
        
        if action == update_now_action:
            self.show_update_now_dialog(ip)
        elif action == schedule_action:
            self.show_schedule_dialog(ip)
        elif action == reboot_action:
            self.reboot_device(ip)
        elif action == check_tr069_action:
            self.check_tr069_status(ip)
    
    def show_schedule_dialog(self, device_ip):
        """Show firmware schedule dialog for a device"""
        # In a real implementation, we would get actual device info
        device_info = {
            "ip": device_ip,
            "manufacturer": "Unknown",
            "model": "Unknown",
            "serial": "Unknown",
            "firmware": "Unknown"
        }
        
        # Try to get manufacturer from the table
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 2).text() == device_ip:
                device_info["manufacturer"] = self.device_table.item(row, 4).text()
                break
        
        dialog = ScheduleUpgradeDialog(self, device_ip, device_info)
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            firmware_path = dialog.get_firmware_path()
            scheduled_time = dialog.get_scheduled_time()
            
            if firmware_path and scheduled_time:
                self.log(f"Firmware upgrade scheduled for device {device_ip} at {scheduled_time.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Schedule the upgrade if server is running
                if self.tr069_server and self.tr069_server.isRunning():
                    self.tr069_server.schedule_firmware_upgrade(device_ip, scheduled_time, firmware_path)
                    QMessageBox.information(self, "Firmware Scheduled", 
                                           f"Firmware upgrade scheduled for device {device_ip} at {scheduled_time.strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    QMessageBox.warning(self, "Server Not Running", 
                                       "TR-069 server is not running. Please start the server to schedule upgrades.")
    
    def show_bulk_upgrade_dialog(self):
        """Show bulk firmware upgrade dialog"""
        # Get selected devices
        selected_ips = []
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 0).checkState() == Qt.Checked:
                ip = self.device_table.item(row, 2).text()
                selected_ips.append(ip)
        
        if not selected_ips:
            QMessageBox.warning(self, "No Devices Selected", "Please select devices to upgrade by checking the boxes in the first column.")
            return
        
        dialog = BulkUpgradeDialog(self, selected_ips)
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            firmware_path = dialog.get_firmware_path()
            scheduled_time = dialog.get_scheduled_time()
            
            if not firmware_path:
                QMessageBox.warning(self, "No Firmware Selected", "Please select a firmware file for the upgrade.")
                return
            
            # Check if server is running
            if not self.tr069_server or not self.tr069_server.isRunning():
                QMessageBox.warning(self, "Server Not Running", "TR-069 server is not running. Please start the server to perform upgrades.")
                return
            
            # Perform bulk upgrade
            if scheduled_time:
                # Scheduled upgrade
                success = self.tr069_server.bulk_upgrade_devices(selected_ips, firmware_path, scheduled_time)
                if success:
                    QMessageBox.information(self, "Bulk Upgrade Scheduled", 
                                           f"Firmware upgrade scheduled for {len(selected_ips)} devices at {scheduled_time.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                # Immediate upgrade
                success = self.tr069_server.bulk_upgrade_devices(selected_ips, firmware_path)
                if success:
                    QMessageBox.information(self, "Bulk Upgrade Initiated", 
                                           f"Firmware upgrade initiated for {len(selected_ips)} devices.")
    
    def add_firmware(self):
        """Add a firmware file to the manager"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Firmware File",
            "",
            "Firmware Files (*.rom *.bin *.img *.zip *.z);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Get additional info
        device_types = ["auto", "yealink", "neron", "grandstream", "fanvil", "alcatel"]
        target_device, ok = QInputDialog.getItem(
            self, 
            "Target Device", 
            "Select target device type:", 
            device_types, 
            0, 
            False
        )
        
        if not ok:
            target_device = "auto"
        
        description, ok = QInputDialog.getText(
            self,
            "Firmware Description",
            "Enter a description for this firmware:"
        )
        
        if not ok:
            description = ""
        
        # Add to manager
        success = self.firmware_manager.add_firmware(
            file_path,
            target_device,
            None,  # Auto-detect version
            description
        )
        
        if success:
            self.log(f"Added firmware: {os.path.basename(file_path)}")
            self.update_firmware_table()
        else:
            QMessageBox.warning(self, "Error", "Failed to add firmware file")
    
    def remove_firmware(self):
        """Remove selected firmware from the manager"""
        selected_rows = self.firmware_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Remove Firmware", "No firmware selected")
            return
        
        row = selected_rows[0].row()
        
        reply = QMessageBox.question(
            self,
            "Remove Firmware",
            "Are you sure you want to remove this firmware?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success = self.firmware_manager.remove_firmware(row)
            if success:
                self.log(f"Removed firmware at index {row}")
                self.update_firmware_table()
            else:
                QMessageBox.warning(self, "Error", "Failed to remove firmware")
    
    def update_firmware_table(self):
        """Update the firmware table with current data"""
        self.firmware_table.setRowCount(0)
        
        firmwares = self.firmware_manager.get_firmwares()
        for firmware in firmwares:
            row = self.firmware_table.rowCount()
            self.firmware_table.insertRow(row)
            
            self.firmware_table.setItem(row, 0, QTableWidgetItem(firmware["filename"]))
            self.firmware_table.setItem(row, 1, QTableWidgetItem(firmware["version"]))
            self.firmware_table.setItem(row, 2, QTableWidgetItem(str(firmware["size"])))
            self.firmware_table.setItem(row, 3, QTableWidgetItem(firmware["target_device_type"]))
            self.firmware_table.setItem(row, 4, QTableWidgetItem(firmware["description"]))
            self.firmware_table.setItem(row, 5, QTableWidgetItem(firmware["date_added"]))
    
    def reboot_device(self, device_ip):
        """Reboot a device"""
        reply = QMessageBox.question(
            self,
            "Reboot Device",
            f"Are you sure you want to reboot device {device_ip}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.log(f"Initiating reboot for device {device_ip}")
            
            # If server is running, use it to reboot the device
            if self.tr069_server and self.tr069_server.isRunning():
                success = self.tr069_server.reboot_device(device_ip)
                if success:
                    QMessageBox.information(self, "Reboot Device", f"Reboot initiated for device {device_ip}")
                else:
                    QMessageBox.warning(self, "Reboot Failed", f"Failed to reboot device {device_ip}")
            else:
                QMessageBox.warning(self, "Server Not Running", "TR-069 server is not running. Please start the server to reboot devices.")
    
    def check_tr069_status(self, device_ip):
        """Check if TR-069 port is open on the device"""
        self.log(f"Checking TR-069 status for {device_ip}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((device_ip, 7547))
            sock.close()
            
            if result == 0:
                self.log(f"TR-069 port is OPEN on {device_ip}")
                QMessageBox.information(self, "TR-069 Status", f"TR-069 port (7547) is OPEN on {device_ip}")
            else:
                self.log(f"TR-069 port is CLOSED on {device_ip}")
                QMessageBox.warning(self, "TR-069 Status", f"TR-069 port (7547) is CLOSED on {device_ip}")
        except Exception as e:
            self.log(f"Error checking TR-069 status: {e}")
            QMessageBox.critical(self, "Error", f"Error checking TR-069 status: {e}")
    
    def start_server(self):
        """Start the TR-069 and firmware servers"""
        # Validate inputs
        if not self.ip_input.text():
            QMessageBox.warning(self, "Input Error", "Please enter a valid IP address")
            return
        
        if not self.username_input.text() or not self.password_input.text():
            QMessageBox.warning(self, "Input Error", "Username and password cannot be empty")
            return
        
        # Check if we have any firmware files
        if not self.firmware_manager.get_firmwares():
            reply = QMessageBox.question(
                self,
                "No Firmware",
                "No firmware files have been added. Add firmware files first?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                self.tabs.setCurrentIndex(1)  # Switch to Firmwares tab
                return
        
        # Check if ports are the same
        if self.port_input.value() == self.http_port_input.value():
            QMessageBox.warning(self, "Port Error", "TR-069 port and HTTP port must be different")
            return
        
        # Get selected firmware (if any)
        selected_firmware = None
        selected_rows = self.firmware_table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            selected_firmware = self.firmware_manager.get_firmware_by_index(row)
        
        if not selected_firmware and self.firmware_manager.get_firmwares():
            # Use the first firmware if none selected
            selected_firmware = self.firmware_manager.get_firmwares()[0]
        
        # Disable inputs
        self.ip_input.setEnabled(False)
        self.port_input.setEnabled(False)
        self.http_port_input.setEnabled(False)
        self.username_input.setEnabled(False)
        self.password_input.setEnabled(False)
        self.device_type_combo.setEnabled(False)
        self.force_upgrade_checkbox.setEnabled(False)
        self.bypass_auth_checkbox.setEnabled(False)
        self.short_lines_checkbox.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Get selected device type
        device_type = self.device_type_combo.currentData()
        
        # Start TR-069 server
        self.tr069_server = TR069Server(
            self.ip_input.text(),
            self.port_input.value(),
            self.username_input.text(),
            self.password_input.text(),
            selected_firmware["path"] if selected_firmware else "",
            self.http_port_input.value(),
            self.force_upgrade_checkbox.isChecked(),
            device_type
        )
        # Set bypass auth flag
        self.tr069_server.bypass_auth = self.bypass_auth_checkbox.isChecked()
        
        self.tr069_server.log_signal.connect(self.log)
        self.tr069_server.status_signal.connect(self.update_status)
        self.tr069_server.device_signal.connect(self.update_device_list)
        self.tr069_server.start()
        
        # Start firmware HTTP server
        self.firmware_server = FirmwareServer(
            self.ip_input.text(),
            self.http_port_input.value(),
            selected_firmware["path"] if selected_firmware else ""
        )
        self.firmware_server.log_signal.connect(self.log)
        self.firmware_server.start()
        
        self.log("Servers started")
        self.log(f"TR-069 server running on {self.ip_input.text()}:{self.port_input.value()}")
        self.log(f"Firmware HTTP server running on {self.ip_input.text()}:{self.http_port_input.value()}")
        self.log(f"Using device type: {device_type}")
        self.log(f"Authentication bypass: {'Enabled' if self.bypass_auth_checkbox.isChecked() else 'Disabled'}")
        self.log(f"Short response lines: {'Enabled' if self.short_lines_checkbox.isChecked() else 'Disabled'}")
        self.log("Waiting for device connections...")
        
        # Update status bar
        # self.statusBar().showMessage("Server running")
    
    def stop_server(self):
        """Stop the TR-069 and firmware servers"""
        if self.tr069_server and self.tr069_server.isRunning():
            self.tr069_server.stop()
        
        if self.firmware_server and self.firmware_server.isRunning():
            self.firmware_server.stop()
        
        # Re-enable inputs
        self.ip_input.setEnabled(True)
        self.port_input.setEnabled(True)
        self.http_port_input.setEnabled(True)
        self.username_input.setEnabled(True)
        self.password_input.setEnabled(True)
        self.device_type_combo.setEnabled(True)
        self.force_upgrade_checkbox.setEnabled(True)
        self.bypass_auth_checkbox.setEnabled(True)
        self.short_lines_checkbox.setEnabled(True)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        self.update_status("Stopped")
        # self.statusBar().showMessage("Server stopped")
    
    @pyqtSlot(str)
    def update_status(self, status):
        """Update the status label"""
        self.status_label.setText(f"Status: {status}")
    
    @pyqtSlot(dict)
    def update_device_list(self, device_info):
        """Update the connected devices list"""
        ip = device_info['ip']
        
        # Check if this device is already in the table
        found = False
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 2).text() == ip:
                # Update existing row
                self.device_table.item(row, 4).setText(device_info.get('manufacturer', 'Unknown'))
                self.device_table.item(row, 5).setText(device_info.get('last_seen', datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                found = True
                break
        
        # If not found, add a new row
        if not found:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            
            # Add checkbox for selection
            checkbox = QTableWidgetItem()
            checkbox.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            checkbox.setCheckState(Qt.Unchecked)
            self.device_table.setItem(row, 0, checkbox)
            
            self.device_table.setItem(row, 1, QTableWidgetItem(str(row + 1)))
            self.device_table.setItem(row, 2, QTableWidgetItem(ip))
            self.device_table.setItem(row, 3, QTableWidgetItem("Unknown"))  # MAC address
            self.device_table.setItem(row, 4, QTableWidgetItem(device_info.get('manufacturer', 'Unknown')))
            self.device_table.setItem(row, 5, QTableWidgetItem(device_info.get('last_seen', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))
            
            # Add action button
            firmware_button = QPushButton("Firmware")
            firmware_button.clicked.connect(lambda checked, ip=ip: self.show_schedule_dialog(ip))
            self.device_table.setCellWidget(row, 6, firmware_button)
        
        # Log the update
        status = device_info.get('status', 'Unknown')
        scheduled = device_info.get('scheduled_upgrade', '')
        
        if scheduled:
            self.log(f"Device update: {ip} - {status} - Upgrade scheduled for {scheduled}")
        else:
            self.log(f"Device update: {ip} - {status}")
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.tr069_server and self.tr069_server.isRunning():
            self.tr069_server.stop()
        
        if self.firmware_server and self.firmware_server.isRunning():
            self.firmware_server.stop()
        
        if self.network_scanner and self.network_scanner.isRunning():
            self.network_scanner.stop()
        
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
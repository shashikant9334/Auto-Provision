from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, 
                          QTableWidget, QTableWidgetItem, QComboBox, QLineEdit, 
                          QHeaderView, QFrame, QApplication, QTabWidget, QSpacerItem,
                          QSizePolicy, QScrollArea, QMessageBox, QProgressDialog, QDialog, 
                          QDialogButtonBox, QCheckBox, QTextEdit, QMainWindow, QStatusBar,
                          QDateTimeEdit, QGridLayout, QFileDialog, QGroupBox, QListWidget,
                          QListWidgetItem)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal, QDateTime, QObject, QUrl, QDate, QTime
from PyQt5.QtGui import QIcon, QColor, QFont
import socket, sqlite3
import os
import logging
import re
import threading
import time
import datetime
import http.server
import socketserver
import urllib.parse
import xml.etree.ElementTree as ET
from functools import partial
from network import NetworkScanner
import requests
import json
import concurrent.futures

# Import template generators
from templates.neron_tem import NeronTemplateGenerator
from templates.yealink_tem import YealinkTemplateGenerator
from templates.grandstream_tem import GrandstreamTemplateGenerator
from templates.cisco_tem import CiscoTemplateGenerator
from templates.alcatel_tem import AlcatelTemplateGenerator
from templates.fanvil_tem import FanvilTemplateGenerator
from templates.generic_tem import GenericTemplateGenerator

# Configure logging to file instead of console
logging.basicConfig(
    filename="C:/Auto/Logs/stdout.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Device Manufacturer Constants
NERON = "Neron"
YEALINK = "Yealink"
GRANDSTREAM = "Grandstream"
ALCATEL = "Alcatel"
CISCO = "Cisco"
FANVIL = "Fanvil"

# Configuration File Types and Manufacturer Requirements
MANUFACTURER_FILE_TYPES = {
    NERON.lower(): ["cfg"],
    YEALINK.lower(): ["boot", "cfg"],
    GRANDSTREAM.lower(): ["xml","cfg"],
    ALCATEL.lower(): ["xml"],
    CISCO.lower(): ["cfg"],
    FANVIL.lower(): ["cfg"]
}

# Comprehensive MAC OUI Database
MAC_OUI_DATABASE = {
    # Yealink OUIs
    '001565': YEALINK,
    '805EC0': YEALINK,
    '805E0C': YEALINK,
    '001F1F': YEALINK,
    '00156D': YEALINK,
    '80C7BB': YEALINK,
    '7C2F80': YEALINK,
    
    # Grandstream OUIs
    '000B82': GRANDSTREAM,
    '00096F': GRANDSTREAM,
    'EC74D7': GRANDSTREAM,
    '000BCD': GRANDSTREAM,
    '080045': GRANDSTREAM,
    '001C11': GRANDSTREAM,
    '002815': GRANDSTREAM,
    
    # Cisco OUIs
    '00036B': CISCO,
    '00075F': CISCO,
    '000F23': CISCO,
    '001A2F': CISCO,
    '001C58': CISCO,
    '001EF7': CISCO,
    '0022BD': CISCO,
    
    # Alcatel OUIs
    '00809F': ALCATEL,
    '00E0B1': ALCATEL,
    '00D0F6': ALCATEL,
    '3C28A6': ALCATEL,
    
    # Fanvil OUIs
    'C8B21E': FANVIL,
    '7C2F80': FANVIL,
    '0C383E': FANVIL,
    
    # Neron OUIs
    '0021F2': NERON,
    'C49894': NERON,
}

class ProvisioningServer(QObject):
    """HTTP server for handling device provisioning requests"""
    
    server_started = pyqtSignal(int)
    server_stopped = pyqtSignal()
    log_message = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.server = None
        self.server_thread = None
        self.port = 8000
        self.running = False
        self.config_dir = "C:/Auto/Configs"
        
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(os.path.join(self.config_dir, "configs"), exist_ok=True)
       
        # Initialize template generators
        self.template_generators = {
            NERON.lower(): NeronTemplateGenerator(),
            YEALINK.lower(): YealinkTemplateGenerator(),
            GRANDSTREAM.lower(): GrandstreamTemplateGenerator(),
            CISCO.lower(): CiscoTemplateGenerator(),
            ALCATEL.lower(): AlcatelTemplateGenerator(),
            FANVIL.upper(): FanvilTemplateGenerator()
        }
        
        # Start server automatically
        self.start_server()
        
    def start_server(self):
        """Start the HTTP server in a separate thread"""
        if self.running:
            return
            
        try:
            outer_self = self
            
            class CustomHandler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, format, *args):
                    outer_self._log_message(format, *args)
                
                def do_GET(self):
                    outer_self._handle_get(self)
                
                def do_POST(self):
                    outer_self._handle_post(self)
            
            # Find an available port
            while self.port < 9000:
                try:
                    self.server = socketserver.TCPServer(("", self.port), CustomHandler)
                    break
                except OSError:
                    self.port += 1
            
            # Start server in a thread
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.running = True
            self.server_started.emit(self.port)
            self.log_message.emit(f"Provisioning server started on port {self.port}")
            
        except Exception as e:
            self.log_message.emit(f"Error starting server: {str(e)}")
    
    def stop_server(self):
        """Stop the HTTP server"""
        if not self.running:
            return
            
        try:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            self.server_stopped.emit()
            self.log_message.emit("Provisioning server stopped")
        except Exception as e:
            self.log_message.emit(f"Error stopping server: {str(e)}")
    
    def _run_server(self):
        """Run the server (called in a thread)"""
        self.server.serve_forever()
    
    def _log_message(self, format, *args):
        """Custom log message handler for the HTTP server"""
        message = format % args
        self.log_message.emit(message)
        logging.info(message)
    
    def _handle_get(self, request_handler):
        """Handle GET requests for config files based on device manufacturer"""
        try:
            path = request_handler.path
            self.log_message.emit(f"GET request for: {path}")
            
            # Handle different file request patterns
            if self._handle_config_file_request(request_handler, path):
                return
            
            # Default handler
            request_handler.send_response(404)
            request_handler.send_header('Content-type', 'text/plain')
            request_handler.end_headers()
            request_handler.wfile.write(b"Not found")
            
        except Exception as e:
            self.log_message.emit(f"Error handling GET request: {str(e)}")
            request_handler.send_response(500)
            request_handler.send_header('Content-type', 'text/plain')
            request_handler.end_headers()
            request_handler.wfile.write(f"Server error: {str(e)}".encode('utf-8'))
    
    def _handle_config_file_request(self, request_handler, path):
        """Handle configuration file requests"""
        # Extract MAC address from various path patterns
        mac = self._extract_mac_from_path(path)
        if not mac:
            return False
        
        # Determine manufacturer
        manufacturer = self._get_manufacturer_from_mac(mac)
        
        # Determine file type and path
        file_path = self._get_config_file_path(path, mac, manufacturer)
        
        if file_path and os.path.exists(file_path):
            self._serve_file(request_handler, file_path)
            return True
        elif file_path:
            # Generate file on demand
            if self._generate_config_file_on_demand(mac, manufacturer, file_path):
                self._serve_file(request_handler, file_path)
                return True
        
        return False
    
    def _extract_mac_from_path(self, path):
        """Extract MAC address from request path"""
        # Handle different path patterns
        patterns = [
            r'/configs/([0-9A-Fa-f]{12})\.',  # /configs/mac.ext
            r'/config/CP_([0-9A-Fa-f]{12})_MPP\.cfg',  # Cisco format
            r'/cfg([0-9A-Fa-f]{12})\.xml',  # Grandstream format
            r'/([0-9A-Fa-f]{12})\.',  # Direct mac.ext
        ]
        
        for pattern in patterns:
            match = re.search(pattern, path)
            if match:
                return match.group(1).upper()
        
        return None
    
    def _get_config_file_path(self, path, mac, manufacturer):
        """Get the appropriate config file path based on manufacturer"""
        manufacturer_lower = manufacturer.lower()
        
        # Handle Cisco special path
        if '/config/' in path:
            return os.path.join(self.config_dir,"config", f"CP_{mac}_MPP.cfg")
        
        # Handle Grandstream cfgmac.xml format
        if path.endswith('.xml') and manufacturer_lower == GRANDSTREAM.lower():
            if f'cfg{mac.lower()}' in path:
                return os.path.join(self.config_dir, "configs", f"cfg{mac.lower()}.xml")
            else:
                return os.path.join(self.config_dir, "configs", f"{mac.lower()}.xml")
        
        # Handle other manufacturers
        if manufacturer_lower in MANUFACTURER_FILE_TYPES:
            file_types = MANUFACTURER_FILE_TYPES[manufacturer_lower]
            
            for file_type in file_types:
                if path.endswith(f'.{file_type}'):
                    return os.path.join(self.config_dir, "configs", f"{mac.lower()}.{file_type}")
        
        # Default fallback
        if path.endswith('.cfg'):
            return os.path.join(self.config_dir, "configs", f"{mac.lower()}.cfg")
        elif path.endswith('.boot'):
            return os.path.join(self.config_dir, "configs", f"{mac.lower()}.boot")
        elif path.endswith('.xml'):
            return os.path.join(self.config_dir, "configs", f"{mac.lower()}.xml")
        
        return None
    
    def _serve_file(self, request_handler, file_path):
        """Serve a file to the client"""
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
            
            # Set content type
            content_type = "text/plain"
            if file_path.endswith('.xml'):
                content_type = "application/xml"
            
            request_handler.send_response(200)
            request_handler.send_header('Content-type', content_type)
            request_handler.send_header('Content-length', len(content))
            request_handler.end_headers()
            request_handler.wfile.write(content)
            
            self.log_message.emit(f"Served config file: {os.path.basename(file_path)}")
            
        except Exception as e:
            self.log_message.emit(f"Error serving file: {e}")
            request_handler.send_response(500)
            request_handler.send_header('Content-type', 'text/plain')
            request_handler.end_headers()
            request_handler.wfile.write(f"Error serving file: {e}".encode('utf-8'))
    
    def _generate_config_file_on_demand(self, mac, manufacturer, file_path):
        """Generate a configuration file on-demand"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            local_ip = self._get_local_ip()
            manufacturer_lower = manufacturer.lower()
            
            if manufacturer_lower in self.template_generators:
                generator = self.template_generators[manufacturer_lower]
                
                # Generate content based on file type
                if file_path.endswith('.boot'):
                    content = generator.generate_boot_file(mac, local_ip, self.port)
                elif file_path.endswith('.xml'):
                    content = generator.generate_xml_file(mac, local_ip, self.port)
                elif file_path.endswith('.cfg'):
                    content = generator.generate_config_file(mac, local_ip, self.port)
                else:
                    content = generator.generate_config_file(mac, local_ip, self.port)
            else:
                # Use generic template
                generator = GenericTemplateGenerator()
                content = generator.generate_config_file(mac, local_ip, self.port)
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            self.log_message.emit(f"Generated config file on-demand: {file_path}")
            return True
            
        except Exception as e:
            self.log_message.emit(f"Error generating config file: {e}")
            return False
    
    def _get_manufacturer_from_mac(self, mac):
        """Determine manufacturer from MAC address"""
        try:
            mac = mac.upper().replace(':', '').replace('-', '')
            oui = mac[:6]
            
            if oui in MAC_OUI_DATABASE:
                return MAC_OUI_DATABASE[oui]
            
            # Check database
            try:
                conn = sqlite3.connect("C:/Auto/Database/Auto.db")
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM brands WHERE mac_address LIKE ?", (oui + '%',))
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    return result[0]
            except Exception:
                pass
            
            return 'Unknown Manufacturer'
            
        except Exception:
            return "Unknown Manufacturer"
    
    def _get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def _handle_post(self, request_handler):
        """Handle POST requests for provisioning"""
        try:
            content_length = int(request_handler.headers['Content-Length'])
            post_data = request_handler.rfile.read(content_length).decode('utf-8')
            parsed_data = urllib.parse.parse_qs(post_data)
            
            if 'provision' in parsed_data:
                device_ip = parsed_data.get('ip', [''])[0]
                device_mac = parsed_data.get('mac', [''])[0]
                device_manufacturer = parsed_data.get('manufacturer', [''])[0]
                
                self.log_message.emit(f"Provisioning request for device {device_ip} (MAC: {device_mac}, Manufacturer: {device_manufacturer})")
                
                config_files = self._generate_config_files(device_mac, device_manufacturer)
                
                if config_files:
                    request_handler.send_response(200)
                    request_handler.send_header('Content-type', 'text/plain')
                    request_handler.end_headers()
                    
                    response = "Provisioning successful\n"
                    local_ip = self._get_local_ip()
                    
                    for config_file in config_files:
                        file_name = os.path.basename(config_file)
                        response += f"CONFIG_URL=http://{local_ip}:{self.port}/configs/{file_name}\n"
                    
                    request_handler.wfile.write(response.encode('utf-8'))
                    self.log_message.emit(f"Provisioning successful for {device_ip}")
                else:
                    request_handler.send_response(404)
                    request_handler.send_header('Content-type', 'text/plain')
                    request_handler.end_headers()
                    request_handler.wfile.write(b"Configuration files not found")
                    self.log_message.emit(f"Configuration files not found for {device_ip}")
            else:
                request_handler.send_response(400)
                request_handler.send_header('Content-type', 'text/plain')
                request_handler.end_headers()
                request_handler.wfile.write(b"Invalid request")
                
        except Exception as e:
            self.log_message.emit(f"Error handling POST request: {str(e)}")
            request_handler.send_response(500)
            request_handler.send_header('Content-type', 'text/plain')
            request_handler.end_headers()
            request_handler.wfile.write(f"Server error: {str(e)}".encode('utf-8'))
    
    def _generate_config_files(self, mac, manufacturer):
        """Generate configuration files for a device"""
        try:
            mac = mac.lower().replace(':', '').replace('-', '')
            configs_dir = os.path.join(self.config_dir, "configs")
            os.makedirs(configs_dir, exist_ok=True)
            
            config_files = []
            manufacturer_lower = manufacturer.lower()
            
            if manufacturer_lower in self.template_generators:
                generator = self.template_generators[manufacturer_lower]
                local_ip = self._get_local_ip()
                
                # Generate files based on manufacturer requirements
                if manufacturer_lower == CISCO.lower():
                    # Cisco special handling
                    cisco_dir = os.path.join(self.config_dir, "config")
                    os.makedirs(cisco_dir, exist_ok=True)
                    
                    cisco_file = os.path.join(cisco_dir, f"CP_{mac.upper()}_MPP.cfg")
                    with open(cisco_file, 'w') as f:
                        f.write(generator.generate_config_file(mac, local_ip, self.port))
                    config_files.append(cisco_file)
                    
                elif manufacturer_lower == GRANDSTREAM.lower():
                    # Grandstream XML files
                    xml_file = os.path.join(configs_dir, f"cfg{mac}.xml")
                    with open(xml_file, 'w') as f:
                        f.write(generator.generate_xml_file(mac, local_ip, self.port))
                    config_files.append(xml_file)
                    
                elif manufacturer_lower == YEALINK.lower():
                    # Yealink boot and cfg files
                    boot_file = os.path.join(configs_dir, f"{mac}.boot")
                    with open(boot_file, 'w') as f:
                        f.write(generator.generate_boot_file(mac, local_ip, self.port))
                    config_files.append(boot_file)
                    
                    cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
                    with open(cfg_file, 'w') as f:
                        f.write(generator.generate_config_file(mac, local_ip, self.port))
                    config_files.append(cfg_file)
                    
                else:
                    # Other manufacturers - generate based on their requirements
                    file_types = MANUFACTURER_FILE_TYPES.get(manufacturer_lower, ["cfg"])
                    
                    for file_type in file_types:
                        if file_type == "cfg":
                            cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
                            with open(cfg_file, 'w') as f:
                                f.write(generator.generate_config_file(mac, local_ip, self.port))
                            config_files.append(cfg_file)
                        elif file_type == "xml":
                            xml_file = os.path.join(configs_dir, f"{mac}.xml")
                            with open(xml_file, 'w') as f:
                                f.write(generator.generate_xml_file(mac, local_ip, self.port))
                            config_files.append(xml_file)
            
            return config_files
            
        except Exception as e:
            self.log_message.emit(f"Error generating config files: {e}")
            return []


class ConfigGenerator:
    """Class to generate configuration files for SIP phones"""
    
    @staticmethod
    def generate_config(device_ip, device_mac, device_manufacturer, extension_data_list):
        """Generate configuration files for a SIP phone with multiple extensions"""
        config_dir = "C:/Auto/Configs/configs"
        os.makedirs(config_dir, exist_ok=True)
        
        mac = device_mac.lower().replace(':', '').replace('-', '')
        local_ip = ConfigGenerator._get_local_ip()
        config_files = []
        manufacturer_lower = device_manufacturer.lower()
        
        # Initialize template generators
        template_generators = {
            NERON.lower(): NeronTemplateGenerator(),
            YEALINK.lower(): YealinkTemplateGenerator(),
            GRANDSTREAM.lower(): GrandstreamTemplateGenerator(),
            CISCO.lower(): CiscoTemplateGenerator(),
            ALCATEL.lower(): AlcatelTemplateGenerator(),
            FANVIL.lower(): FanvilTemplateGenerator()
        }
        
        if manufacturer_lower in template_generators:
            generator = template_generators[manufacturer_lower]
            config_files = generator.generate_all_config_files_with_extensions(
                mac, config_dir, local_ip, 8000, extension_data_list
            )
        else:
            # Use generic template
            generator = GenericTemplateGenerator()
            config_files = generator.generate_all_config_files_with_extensions(
                mac, config_dir, local_ip, 8000, extension_data_list
            )
        
        return config_files
    
    @staticmethod
    def _get_local_ip():
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"


class ProvisioningAPI:
    """API for provisioning SIP phones"""
    
    @staticmethod
    def provision_device(device_ip, device_mac, extension_data_list):
        """Provision a device with the given extension data"""
        try:
            manufacturer = ProvisioningAPI.get_manufacturer_from_mac(device_mac)
            config_files = ConfigGenerator.generate_config(device_ip, device_mac, manufacturer, extension_data_list)
            
            if not config_files:
                return False, "Failed to generate configuration files"
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            mac = device_mac.lower().replace(":", "").replace("-", "")
            extensions_str = ", ".join([ext_data["extension"] for ext_data in extension_data_list])
            config_files_str = ", ".join([os.path.basename(file) for file in config_files])
            
            print("Provisioning URLs:")
            for config_file in config_files:
                file_name = os.path.basename(config_file)
                print(f"http://{local_ip}:8000/configs/{file_name}")
            
            return True, f"Device at {device_ip} ({manufacturer}) has been provisioned with extensions: {extensions_str}. Configuration files: {config_files_str}"
                
        except Exception as e:
            return False, f"Provisioning failed: {str(e)}"
    
    @staticmethod
    def provision_devices_bulk(device_extension_pairs):
        """Provision multiple devices with individual extension data"""
        results = []
        success_count = 0
        failure_count = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_device = {
                executor.submit(
                    ProvisioningAPI.provision_device, 
                    device['ip'], 
                    device['mac'], 
                    extensions
                ): (device, extensions) for device, extensions in device_extension_pairs
            }
            
            for future in concurrent.futures.as_completed(future_to_device):
                device, extensions = future_to_device[future]
                try:
                    success, message = future.result()
                    if success:
                        success_count += 1
                    else:
                        failure_count += 1
                    
                    results.append({
                        'device': device,
                        'extensions': extensions,
                        'success': success,
                        'message': message
                    })
                except Exception as e:
                    failure_count += 1
                    results.append({
                        'device': device,
                        'extensions': extensions,
                        'success': False,
                        'message': f"Error: {str(e)}"
                    })
        
        return {
            'total': len(device_extension_pairs),
            'success': success_count,
            'failure': failure_count,
            'results': results
        }
    
    @staticmethod
    def get_manufacturer_from_mac(mac):
        """Determine manufacturer from MAC address"""
        try:
            mac = mac.upper().replace(':', '').replace('-', '')
            oui = mac[:6]
            
            if oui in MAC_OUI_DATABASE:
                return MAC_OUI_DATABASE[oui]
            
            try:
                conn = sqlite3.connect("C:/Auto/Database/Auto.db")
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM brands WHERE mac_address LIKE ?", (oui + '%',))
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    return result[0]
            except Exception as e:
                print(f"Error querying database: {e}")
            
            return 'Unknown Manufacturer'
            
        except Exception as e:
            print(f"Error determining manufacturer: {e}")
            return "Unknown Manufacturer"


class BulkProvisioningDialog(QDialog):
    """Dialog for bulk provisioning multiple SIP phones with individual extension selection."""

    def __init__(self, device_list, server_port, parent=None):
        super().__init__(parent)
        self.device_list = device_list
        self.server_port = server_port
        self.setWindowTitle(f"Bulk Provisioning - {len(device_list)} Devices")
        self.setMinimumSize(1400, 800)
        
        # Store device-specific extension data
        self.device_extensions = {}  # device_index -> [extension_data_list]
        
        # Initialize with empty extension lists for each device
        for i in range(len(device_list)):
            self.device_extensions[i] = []

        # Main Layout (Horizontal Split)
        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(10)

        # === Left Side: Device List ===
        left_frame = QFrame()
        left_frame.setFrameShape(QFrame.StyledPanel)
        left_frame.setStyleSheet("background-color: #f8f9fa; padding: 10px;")
        left_layout = QVBoxLayout(left_frame)

        device_header_layout = QHBoxLayout()
        device_info_label = QLabel("<b>Selected Devices</b>")
        device_info_label.setStyleSheet("font-size: 14px;")
        self.select_all_checkbox = QCheckBox("Select All")
        self.select_all_checkbox.setChecked(True)
        self.select_all_checkbox.stateChanged.connect(self.toggle_select_all)
        device_header_layout.addWidget(device_info_label)
        device_header_layout.addStretch()
        device_header_layout.addWidget(self.select_all_checkbox)
        left_layout.addLayout(device_header_layout)

        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(["Select", "IP Address", "MAC Address", "Manufacturer", "Current Extension", "Assigned Extensions"])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.verticalHeader().setVisible(False)
        self.device_table.itemSelectionChanged.connect(self.device_selection_changed)
        left_layout.addWidget(self.device_table)
        self.populate_device_table()

        main_layout.addWidget(left_frame, 2)

        # === Right Side: Extensions Management ===
        right_frame = QFrame()
        right_frame.setFrameShape(QFrame.StyledPanel)
        right_frame.setStyleSheet("background-color: #f8f9fa; padding: 10px;")
        right_layout = QVBoxLayout(right_frame)

        # Device-specific extensions section
        device_ext_header = QLabel("<b>Extensions for Selected Device</b>")
        device_ext_header.setStyleSheet("font-size: 14px;")
        right_layout.addWidget(device_ext_header)

        self.selected_device_label = QLabel("No device selected")
        self.selected_device_label.setStyleSheet("color: #666; font-style: italic;")
        right_layout.addWidget(self.selected_device_label)

        # Extensions list for selected device
        ext_list_layout = QHBoxLayout()
        ext_list_label = QLabel("Assigned Extensions:")
        self.add_ext_btn = QPushButton("Add Extension")
        self.add_ext_btn.clicked.connect(self.add_extension_to_device)
        self.add_ext_btn.setEnabled(False)
        ext_list_layout.addWidget(ext_list_label)
        ext_list_layout.addStretch()
        ext_list_layout.addWidget(self.add_ext_btn)
        right_layout.addLayout(ext_list_layout)

        self.device_extensions_list = QListWidget()
        self.device_extensions_list.setMinimumHeight(120)
        self.device_extensions_list.itemClicked.connect(self.extension_selected)
        right_layout.addWidget(self.device_extensions_list)

        # Extension Details Section
        self.ext_details_frame = QFrame()
        self.ext_details_frame.setFrameShape(QFrame.StyledPanel)
        self.ext_details_frame.setStyleSheet("background-color: #ffffff; padding: 8px;")
        ext_details_layout = QVBoxLayout(self.ext_details_frame)

        ext_details_label = QLabel("<b>Extension Details</b>")
        ext_details_layout.addWidget(ext_details_label)

        ext_form_layout = QGridLayout()
        ext_form_layout.setColumnStretch(1, 1)

        ext_form_layout.addWidget(QLabel("Extension:"), 0, 0)
        self.ext_combo = QComboBox()
        self.ext_combo.setMinimumWidth(200)
        self.load_extensions()
        self.ext_combo.currentIndexChanged.connect(self.update_extension_fields)
        ext_form_layout.addWidget(self.ext_combo, 0, 1)

        ext_form_layout.addWidget(QLabel("Username:"), 1, 0)
        self.username_input = QLineEdit()
        ext_form_layout.addWidget(self.username_input, 1, 1)

        ext_form_layout.addWidget(QLabel("Password:"), 2, 0)
        self.password_input = QLineEdit()
        ext_form_layout.addWidget(self.password_input, 2, 1)

        ext_form_layout.addWidget(QLabel("Domain:"), 3, 0)
        self.domain_input = QLineEdit()
        ext_form_layout.addWidget(self.domain_input, 3, 1)

        ext_details_layout.addLayout(ext_form_layout)

        # Extension Action Buttons
        ext_action_layout = QHBoxLayout()
        self.update_ext_btn = QPushButton("Update")
        self.update_ext_btn.clicked.connect(self.update_extension)
        self.remove_ext_btn = QPushButton("Remove")
        self.remove_ext_btn.clicked.connect(self.remove_extension)
        ext_action_layout.addWidget(self.update_ext_btn)
        ext_action_layout.addWidget(self.remove_ext_btn)
        ext_action_layout.addStretch()
        ext_details_layout.addLayout(ext_action_layout)

        right_layout.addWidget(self.ext_details_frame)
        self.ext_details_frame.setEnabled(False)

        right_layout.addStretch()

        # Bottom Buttons
        bottom_button_layout = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.provision_btn = QPushButton("Provision All Selected Devices")
        self.provision_btn.clicked.connect(self.provision_devices)
        bottom_button_layout.addWidget(self.cancel_btn)
        bottom_button_layout.addWidget(self.provision_btn)
        right_layout.addLayout(bottom_button_layout)

        main_layout.addWidget(right_frame, 1)

        self.update_extension_fields()

    def populate_device_table(self):
        self.device_table.setRowCount(len(self.device_list))
        for row, device in enumerate(self.device_list):
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            checkbox_widget = QWidget()
            checkbox_layout = QHBoxLayout(checkbox_widget)
            checkbox_layout.addWidget(checkbox)
            checkbox_layout.setAlignment(Qt.AlignCenter)
            checkbox_layout.setContentsMargins(0, 0, 0, 0)
            self.device_table.setCellWidget(row, 0, checkbox_widget)
            
            self.device_table.setItem(row, 1, QTableWidgetItem(device.get('ip', '')))
            self.device_table.setItem(row, 2, QTableWidgetItem(device.get('mac', '')))
            self.device_table.setItem(row, 3, QTableWidgetItem(device.get('manufacturer', '')))
            self.device_table.setItem(row, 4, QTableWidgetItem(device.get('extension', 'None')))
            self.device_table.setItem(row, 5, QTableWidgetItem("0 extensions"))

    def toggle_select_all(self, state):
        for row in range(self.device_table.rowCount()):
            checkbox = self.device_table.cellWidget(row, 0).findChild(QCheckBox)
            if checkbox:
                checkbox.setChecked(state == Qt.Checked)

    def device_selection_changed(self):
        """Handle device selection change"""
        current_row = self.device_table.currentRow()
        if current_row >= 0:
            device = self.device_list[current_row]
            self.selected_device_label.setText(f"Device: {device['ip']} ({device['mac']})")
            self.add_ext_btn.setEnabled(True)
            self.load_device_extensions(current_row)
        else:
            self.selected_device_label.setText("No device selected")
            self.add_ext_btn.setEnabled(False)
            self.device_extensions_list.clear()
            self.ext_details_frame.setEnabled(False)

    def load_device_extensions(self, device_index):
        """Load extensions for the selected device"""
        self.device_extensions_list.clear()
        extensions = self.device_extensions.get(device_index, [])
        
        for ext_data in extensions:
            item_text = f"{ext_data['extension']} ({ext_data['username']}@{ext_data['domain']})"
            self.device_extensions_list.addItem(item_text)
        
        # Update the table to show extension count
        self.device_table.setItem(device_index, 5, QTableWidgetItem(f"{len(extensions)} extensions"))

    def load_extensions(self):
        try:
            conn = sqlite3.connect("C:/Auto/Database/Auto.db")
            cursor = conn.cursor()
            cursor.execute("SELECT display_name FROM extension_list ORDER BY display_name")
            extensions = cursor.fetchall()
            conn.close()
            for ext in extensions:
                self.ext_combo.addItem(ext[0], ext[0])
        except Exception as e:
            print(f"Error loading extensions: {e}")
            self.ext_combo.addItems(["1000", "1001", "1008"])

    def update_extension_fields(self):
        selected_ext = self.ext_combo.currentData()
        if selected_ext:
            data = self.get_extension_data(selected_ext)
            self.username_input.setText(data["username"])
            self.password_input.setText(data["password"])
            self.domain_input.setText(data["domain"])

    def get_extension_data(self, extension):
        try:
            conn = sqlite3.connect("C:/Auto/Database/Auto.db")
            cursor = conn.cursor()
            cursor.execute("SELECT display_name, username, password, domain FROM extension_list WHERE display_name = ?", (extension,))
            data = cursor.fetchone()
            conn.close()
            if data:
                return {"extension": data[0], "username": data[1], "password": data[2], "domain": data[3]}
        except Exception as e:
            print(f"Error fetching extension data: {e}")
        return {"extension": extension, "username": extension, "password": "password", "domain": "sip.example.com"}

    def add_extension_to_device(self):
        """Add extension to the currently selected device"""
        current_row = self.device_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Device Selected", "Please select a device first.")
            return

        selected_ext = self.ext_combo.currentData()
        if not selected_ext:
            QMessageBox.warning(self, "Input Error", "Please select an extension.")
            return

        # Check if extension already exists for this device
        device_extensions = self.device_extensions.get(current_row, [])
        if any(ext["extension"] == selected_ext for ext in device_extensions):
            QMessageBox.warning(self, "Duplicate Extension", f"Extension {selected_ext} already added to this device.")
            return

        extension_data = {
            "extension": selected_ext,
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "domain": self.domain_input.text()
        }
        
        if not all([extension_data["username"], extension_data["password"], extension_data["domain"]]):
            QMessageBox.warning(self, "Input Error", "All extension fields must be filled.")
            return

        # Add to device extensions
        if current_row not in self.device_extensions:
            self.device_extensions[current_row] = []
        self.device_extensions[current_row].append(extension_data)

        # Refresh the display
        self.load_device_extensions(current_row)
        
        # Select the newly added extension
        self.device_extensions_list.setCurrentRow(len(self.device_extensions[current_row]) - 1)
        self.extension_selected(self.device_extensions_list.currentItem())

    def extension_selected(self, item):
        if not item:
            self.ext_details_frame.setEnabled(False)
            return
        
        current_row = self.device_table.currentRow()
        if current_row < 0:
            return
            
        self.ext_details_frame.setEnabled(True)
        index = self.device_extensions_list.row(item)
        extensions = self.device_extensions.get(current_row, [])
        
        if index < len(extensions):
            data = extensions[index]
            idx = self.ext_combo.findData(data["extension"])
            if idx >= 0:
                self.ext_combo.setCurrentIndex(idx)
            self.username_input.setText(data["username"])
            self.password_input.setText(data["password"])
            self.domain_input.setText(data["domain"])

    def update_extension(self):
        current_row = self.device_table.currentRow()
        current_item = self.device_extensions_list.currentItem()
        if current_row < 0 or not current_item:
            return
        
        index = self.device_extensions_list.row(current_item)
        extensions = self.device_extensions.get(current_row, [])
        
        if index < len(extensions):
            extensions[index] = {
                "extension": self.ext_combo.currentData(),
                "username": self.username_input.text(),
                "password": self.password_input.text(),
                "domain": self.domain_input.text()
            }
            self.load_device_extensions(current_row)
            self.device_extensions_list.setCurrentRow(index)

    def remove_extension(self):
        current_row = self.device_table.currentRow()
        current_item = self.device_extensions_list.currentItem()
        if current_row < 0 or not current_item:
            return
        
        index = self.device_extensions_list.row(current_item)
        extensions = self.device_extensions.get(current_row, [])
        
        if index < len(extensions):
            extensions.pop(index)
            self.load_device_extensions(current_row)
            if len(extensions) == 0:
                self.ext_details_frame.setEnabled(False)

    def get_selected_devices_with_extensions(self):
        """Get selected devices with their assigned extensions"""
        selected_device_extensions = []
        
        for row in range(self.device_table.rowCount()):
            checkbox = self.device_table.cellWidget(row, 0).findChild(QCheckBox)
            if checkbox and checkbox.isChecked():
                device = self.device_list[row]
                extensions = self.device_extensions.get(row, [])
                if extensions:  # Only include devices with extensions
                    selected_device_extensions.append((device, extensions))
        
        return selected_device_extensions

    def provision_devices(self):
        selected_device_extensions = self.get_selected_devices_with_extensions()
        
        if not selected_device_extensions:
            QMessageBox.warning(self, "No Devices with Extensions", 
                              "Please select at least one device and assign extensions to it.")
            return

        # Show progress dialog
        progress = QProgressDialog("Provisioning devices...", "Cancel", 0, len(selected_device_extensions), self)
        progress.setWindowModality(Qt.WindowModal)
        progress.show()

        # Perform bulk provisioning
        results = ProvisioningAPI.provision_devices_bulk(selected_device_extensions)
        
        progress.close()

        # Show results
        success_count = results['success']
        failure_count = results['failure']
        total_count = results['total']
        
        result_message = f"Provisioning completed:\n"
        result_message += f"Total devices: {total_count}\n"
        result_message += f"Successful: {success_count}\n"
        result_message += f"Failed: {failure_count}\n\n"
        
        if failure_count > 0:
            result_message += "Failed devices:\n"
            for result in results['results']:
                if not result['success']:
                    device = result['device']
                    result_message += f"- {device['ip']} ({device['mac']}): {result['message']}\n"

        QMessageBox.information(self, "Bulk Provisioning Results", result_message)
        self.accept()


class ProvisioningDialog(QDialog):
    """Dialog for auto-provisioning SIP phones"""
    def __init__(self, device_data, server_port, parent=None):
        super().__init__(parent)
        self.device_data = device_data
        self.server_port = server_port
        self.setWindowTitle(f"Auto Provisioning - {device_data['ip']}")
        self.setMinimumWidth(700)
        self.setMinimumHeight(700)
        
        self.extensions_data = []
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Device info section
        info_frame = QFrame()
        info_frame.setFrameShape(QFrame.NoFrame)
        info_frame.setStyleSheet("background-color: #f8f9fa; padding: 0px;")
        
        info_layout = QVBoxLayout(info_frame)
        
        device_info_label = QLabel("<b>Device Information</b>")
        device_info_label.setStyleSheet("font-size: 14px;")
        info_layout.addWidget(device_info_label)
        
        form_layout = QGridLayout()
        form_layout.setColumnStretch(1, 1)
        
        ip_label = QLabel("IP Address:")
        self.ip_input = QLineEdit(device_data['ip'])
        form_layout.addWidget(ip_label, 0, 0)
        form_layout.addWidget(self.ip_input, 0, 1)
        
        mac_label = QLabel("MAC Address:")
        self.mac_input = QLineEdit(device_data['mac'])
        form_layout.addWidget(mac_label, 1, 0)
        form_layout.addWidget(self.mac_input, 1, 1)
        
        manufacturer_label = QLabel("Manufacturer:")
        self.manufacturer_input = QLineEdit(device_data['manufacturer'])
        form_layout.addWidget(manufacturer_label, 2, 0)
        form_layout.addWidget(self.manufacturer_input, 2, 1)
        
        info_layout.addLayout(form_layout)
        layout.addWidget(info_frame)
        
        # Extensions section
        ext_frame = QFrame()
        ext_frame.setFrameShape(QFrame.NoFrame)
        ext_frame.setStyleSheet("background-color: #f8f9fa; padding: 0px;")
        
        ext_layout = QVBoxLayout(ext_frame)
        
        ext_header_layout = QHBoxLayout()
        ext_info_label = QLabel("<b>Extensions</b>")
        ext_info_label.setStyleSheet("font-size: 14px;")
        ext_header_layout.addWidget(ext_info_label)
        
        self.add_ext_btn = QPushButton("Add Extension")
        self.add_ext_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 4px 8px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.add_ext_btn.clicked.connect(self.add_extension)
        ext_header_layout.addStretch()
        ext_header_layout.addWidget(self.add_ext_btn)
        
        ext_layout.addLayout(ext_header_layout)
        
        self.extensions_list = QListWidget()
        self.extensions_list.setMinimumHeight(100)
        self.extensions_list.itemClicked.connect(self.extension_selected)
        ext_layout.addWidget(self.extensions_list)
        
        # Extension details
        self.ext_details_frame = QFrame()
        self.ext_details_frame.setFrameShape(QFrame.StyledPanel)
        self.ext_details_frame.setStyleSheet("background-color: #ffffff; padding: 0px;")
        
        ext_details_layout = QVBoxLayout(self.ext_details_frame)
        
        ext_details_label = QLabel("<b>Extension Details</b>")
        ext_details_label.setStyleSheet("font-size: 12px;")
        ext_details_layout.addWidget(ext_details_label)
        
        ext_form_layout = QGridLayout()
        ext_form_layout.setColumnStretch(1, 1)
        
        ext_label = QLabel("Extension:")
        self.ext_combo = QComboBox()
        self.ext_combo.setMinimumWidth(200)
        self.load_extensions()
        self.ext_combo.currentIndexChanged.connect(self.update_extension_fields)
        ext_form_layout.addWidget(ext_label, 0, 0)
        ext_form_layout.addWidget(self.ext_combo, 0, 1)
        
        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        ext_form_layout.addWidget(username_label, 1, 0)
        ext_form_layout.addWidget(self.username_input, 1, 1)
        
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        ext_form_layout.addWidget(password_label, 2, 0)
        ext_form_layout.addWidget(self.password_input, 2, 1)
        
        domain_label = QLabel("Domain:")
        self.domain_input = QLineEdit()
        ext_form_layout.addWidget(domain_label, 3, 0)
        ext_form_layout.addWidget(self.domain_input, 3, 1)
        
        ext_details_layout.addLayout(ext_form_layout)
        
        ext_action_layout = QHBoxLayout()
        
        self.update_ext_btn = QPushButton("Update")
        self.update_ext_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 4px 8px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        self.update_ext_btn.clicked.connect(self.update_extension)
        
        self.remove_ext_btn = QPushButton("Remove")
        self.remove_ext_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 4px 8px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        self.remove_ext_btn.clicked.connect(self.remove_extension)
        
        ext_action_layout.addWidget(self.update_ext_btn)
        ext_action_layout.addWidget(self.remove_ext_btn)
        ext_action_layout.addStretch()
        
        ext_details_layout.addLayout(ext_action_layout)
        
        ext_layout.addWidget(self.ext_details_frame)
        layout.addWidget(ext_frame)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedHeight(40)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                border: 1px solid #ddd;
                border-radius: 2px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.cancel_btn.clicked.connect(self.reject)
        
        self.provision_btn = QPushButton("Provision Device")
        self.provision_btn.setFixedHeight(40)
        self.provision_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 2px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.provision_btn.clicked.connect(self.provision_device)
        
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.provision_btn)
        
        layout.addLayout(button_layout)
        
        self.ext_details_frame.setEnabled(False)
        self.update_extension_fields()
        
        if device_data['extension'] and device_data['extension'] not in ["No Extension", "Error"]:
            self.add_initial_extension(device_data['extension'])
    
    def add_initial_extension(self, extension):
        """Add the initial extension from device data"""
        extension_data = self.get_extension_data(extension)
        self.extensions_data.append(extension_data)
        
        item = QListWidgetItem(f"{extension} ({extension_data['username']}@{extension_data['domain']})")
        self.extensions_list.addItem(item)
    
    def load_extensions(self):
        """Load available extensions from the database"""
        try:
            conn = sqlite3.connect("C:/Auto/Database/Auto.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT display_name, username FROM extension_list ORDER BY display_name")
            extensions = cursor.fetchall()
            
            conn.close()
            
            for ext in extensions:
                self.ext_combo.addItem(f"{ext[0]}", ext[0])
                
        except Exception as e:
            print(f"Error loading extensions: {e}")
            self.ext_combo.addItem("1000", "1000")
            self.ext_combo.addItem("1001", "1001")
            self.ext_combo.addItem("1008", "1008")
    
    def update_extension_fields(self):
        """Update extension fields based on selected extension"""
        selected_ext = self.ext_combo.currentData()
        
        if selected_ext:
            extension_data = self.get_extension_data(selected_ext)
            
            self.username_input.setText(extension_data["username"])
            self.password_input.setText(extension_data["password"])
            self.domain_input.setText(extension_data["domain"])
    
    def get_extension_data(self, extension):
        """Get full extension data from the database"""
        try:
            conn = sqlite3.connect("C:/Auto/Database/Auto.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT display_name, username, password, domain FROM extension_list WHERE display_name = ?", (extension,))
            ext_data = cursor.fetchone()
            
            conn.close()
            
            if ext_data:
                return {
                    "extension": ext_data[0],
                    "username": ext_data[1],
                    "password": ext_data[2],
                    "domain": ext_data[3]
                }
            else:
                return {
                    "extension": extension,
                    "username": extension,
                    "password": "password",
                    "domain": "sip.example.com"
                }
                
        except Exception as e:
            print(f"Error getting extension data: {e}")
            return {
                "extension": extension,
                "username": extension,
                "password": "password",
                "domain": "sip.example.com"
            }
    
    def add_extension(self):
        """Add an extension to the list"""
        selected_ext = self.ext_combo.currentData()
        
        if not selected_ext:
            QMessageBox.warning(self, "Input Error", "Please select an extension.")
            return
        
        for ext_data in self.extensions_data:
            if ext_data["extension"] == selected_ext:
                QMessageBox.warning(self, "Duplicate Extension", f"Extension {selected_ext} is already in the list.")
                return
        
        extension_data = {
            "extension": selected_ext,
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "domain": self.domain_input.text()
        }
        
        if not extension_data["username"] or not extension_data["password"] or not extension_data["domain"]:
            QMessageBox.warning(self, "Input Error", "All extension fields are required.")
            return
        
        self.extensions_data.append(extension_data)
        
        item = QListWidgetItem(f"{extension_data['extension']} ({extension_data['username']}@{extension_data['domain']})")
        self.extensions_list.addItem(item)
        
        self.extensions_list.setCurrentItem(item)
        self.extension_selected(item)
    
    def extension_selected(self, item):
        """Handle extension selection from the list"""
        if not item:
            self.ext_details_frame.setEnabled(False)
            return
        
        self.ext_details_frame.setEnabled(True)
        
        index = self.extensions_list.row(item)
        extension_data = self.extensions_data[index]
        
        ext_index = self.ext_combo.findData(extension_data["extension"])
        if ext_index >= 0:
            self.ext_combo.setCurrentIndex(ext_index)
        
        self.username_input.setText(extension_data["username"])
        self.password_input.setText(extension_data["password"])
        self.domain_input.setText(extension_data["domain"])
    
    def update_extension(self):
        """Update the selected extension"""
        current_item = self.extensions_list.currentItem()
        if not current_item:
            return
        
        index = self.extensions_list.row(current_item)
        
        extension_data = {
            "extension": self.ext_combo.currentData(),
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "domain": self.domain_input.text()
        }
        
        if not extension_data["extension"] or not extension_data["username"] or not extension_data["password"] or not extension_data["domain"]:
            QMessageBox.warning(self, "Input Error", "All extension fields are required.")
            return
        
        self.extensions_data[index] = extension_data
        current_item.setText(f"{extension_data['extension']} ({extension_data['username']}@{extension_data['domain']})")
    
    def remove_extension(self):
        """Remove the selected extension"""
        current_item = self.extensions_list.currentItem()
        if not current_item:
            return
        
        index = self.extensions_list.row(current_item)
        self.extensions_data.pop(index)
        self.extensions_list.takeItem(index)
        
        if self.extensions_list.count() == 0:
            self.ext_details_frame.setEnabled(False)
    
    def provision_device(self):
        """Handle the provisioning process"""
        if not self.extensions_data:
            QMessageBox.warning(self, "Input Error", "Please add at least one extension.")
            return
        
        updated_device_data = {
            'ip': self.ip_input.text(),
            'mac': self.mac_input.text(),
            'manufacturer': self.manufacturer_input.text()
        }
        
        if not updated_device_data['ip'] or not updated_device_data['mac']:
            QMessageBox.warning(self, "Input Error", "IP Address and MAC Address are required.")
            return
        
        # Call the provisioning API with the updated data
        success, message = ProvisioningAPI.provision_device(
            updated_device_data['ip'],
            updated_device_data['mac'],
            self.extensions_data
        )
        
        # Show result message
        if success:
            QMessageBox.information(
                self, 
                "Provisioning Successful", 
                message
            )
            
            # Update the device in the database with the primary extension
            primary_extension = self.extensions_data[0]["extension"] if self.extensions_data else ""
            self.update_device_in_database(updated_device_data, primary_extension)
            
            self.accept()
        else:
            QMessageBox.critical(
                self,
                "Provisioning Failed",
                message
            )
    
    def update_device_in_database(self, device_data, extension):
        """Update the device in the database with the new extension"""
        try:
            conn = sqlite3.connect("C:/Auto/Database/Auto.db")
            cursor = conn.cursor()
            
            # Check if device exists
            cursor.execute("SELECT id FROM devices WHERE mac_address = ?", (device_data['mac'],))
            device = cursor.fetchone()
            
            if device:
                # Update existing device
                cursor.execute(
                    "UPDATE devices SET ip_address = ?, manufacturer = ?, extension = ?, last_updated = ? WHERE mac_address = ?",
                    (device_data['ip'], device_data['manufacturer'], extension, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), device_data['mac'])
                )
            else:
                # Insert new device
                cursor.execute(
                    "INSERT INTO devices (ip_address, mac_address, manufacturer, extension, last_updated) VALUES (?, ?, ?, ?, ?)",
                    (device_data['ip'], device_data['mac'], device_data['manufacturer'], extension, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error updating device in database: {e}")


class LogViewerDialog(QDialog):
    """Dialog to view server logs"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Server Logs")
        self.setMinimumSize(700, 500)
        
        layout = QVBoxLayout(self)
        
        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier New", 10))
        
        layout.addWidget(self.log_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        clear_btn = QPushButton("Clear Logs")
        clear_btn.clicked.connect(self.clear_logs)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        
        button_layout.addWidget(clear_btn)
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def add_log(self, message):
        """Add a log message to the viewer"""
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.log_text.append(f"[{timestamp}] {message}")
    
    def clear_logs(self):
        """Clear all log messages"""
        self.log_text.clear()


class ProvisionPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = None
        self.devices = []
        
        # Initialize the provisioning server
        self.provision_server = ProvisioningServer(self)
        self.provision_server.log_message.connect(self.on_server_log)
        self.server_port = self.provision_server.port
        
        # Create log viewer dialog
        self.log_viewer = LogViewerDialog(self)

        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Filter and Action Section
        filter_frame = QFrame()
        filter_frame.setFrameShape(QFrame.StyledPanel)
        filter_frame.setStyleSheet("background-color: white; border-radius: 4px;")
        
        filter_layout = QVBoxLayout(filter_frame)
        
        # IP Range Filter
        ip_filter_layout = QHBoxLayout()
        
        ip_range_label = QLabel("IP Address:")
        
        self.ip_range_input = QLineEdit()
        self.ip_range_input.setPlaceholderText("Enter IP range (e.g., 192.168.1.0/24 or 192.168.1.1-254)")
        self.ip_range_input.setMinimumWidth(300)
        self.ip_range_input.setStyleSheet("border:1px solid gray;height:35px;border-radius:0px")
        
        # Auto-detect and fill IP range
        self.auto_detect_ip_range()
        
        # Add checkbox for scanning all devices
        self.scan_all_checkbox = QCheckBox("Scan all network devices")
        self.scan_all_checkbox.setToolTip("When enabled, scan all network devices. When disabled, only scan devices with MAC addresses in the database.")
        
        self.scan_btn = QPushButton("Scan Network", self)
        self.scan_btn.setIcon(QIcon.fromTheme("search"))
        self.scan_btn.setStyleSheet("""
    QPushButton {
        background-color: #f0f0f0;
        color: black;
        border: 1px solid #999;
        padding: 8px 15px;
        border-radius: 0px;
    }
    QPushButton:hover {
        background-color: #cce7ff;
        border: 1px solid #0078d7;
    }
        """)
        
        self.view_logs_btn = QPushButton("View Logs")
        self.view_logs_btn.setStyleSheet("""
    QPushButton {
        background-color: #f0f0f0;
        color: black;
        border: 1px solid #999;
        padding: 8px 15px;
        border-radius: 0px;
    }
    QPushButton:hover {
        background-color: #cce7ff;
        border: 1px solid #0078d7;
    }
        """)
        self.view_logs_btn.clicked.connect(self.show_logs)
      
        ip_filter_layout.addWidget(ip_range_label)
        ip_filter_layout.addWidget(self.ip_range_input)
        ip_filter_layout.addWidget(self.scan_all_checkbox)
        ip_filter_layout.addWidget(self.scan_btn)
        ip_filter_layout.addWidget(self.view_logs_btn)
        filter_layout.addLayout(ip_filter_layout)
        
        # Status label
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #7f8c8d;")
        filter_layout.addWidget(self.status_label)
        
        main_layout.addWidget(filter_frame)
        
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
        
        # Bulk provisioning button
        self.bulk_provision_btn = QPushButton("Bulk Provision")
        self.bulk_provision_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.bulk_provision_btn.clicked.connect(self.open_bulk_provisioning)
        
        search_layout.addWidget(self.bulk_provision_btn)
        search_layout.addStretch()
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        
        table_layout.addLayout(search_layout)
        
        # Device Table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(7)
        headers = ["S.N.", "IP ADDRESS", "MAC ADDRESS", "EXTENSION",  "MANUFACTURER", "LAST UPDATED", "ACTION"]
        self.device_table.setHorizontalHeaderLabels(headers)
        self.device_table.horizontalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 5px;
                border: none;
                border-bottom: 1px solid #ddd;
            }
        """)
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.verticalHeader().setVisible(False)
        
        # Add select all checkbox in header
        self.select_all_checkbox_header = QCheckBox()
        self.select_all_checkbox_header.stateChanged.connect(self.toggle_select_all_devices)
        self.device_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.device_table.horizontalHeader().setDefaultSectionSize(50)
        
        table_layout.addWidget(self.device_table)
        
        main_layout.addWidget(table_frame)

        # Connect actions
        self.scan_btn.clicked.connect(self.start_scan)
        self.search_input.textChanged.connect(self.filter_table)
        
        self.refresh_device_list() 
    
    def toggle_select_all_devices(self, state):
        """Toggle selection of all devices in the table"""
        for row in range(self.device_table.rowCount()):
            checkbox_widget = self.device_table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox:
                    checkbox.setChecked(state == Qt.Checked)
    
    def open_bulk_provisioning(self):
        """Open the bulk provisioning dialog"""
        # Get selected devices
        selected_devices = []
        for row in range(self.device_table.rowCount()):
            checkbox_widget = self.device_table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    selected_devices.append(self.devices[row])
        
        if not selected_devices:
            QMessageBox.warning(self, "Selection Required", "Please select at least one device for bulk provisioning.")
            return
        
        # Open the bulk provisioning dialog
        dialog = BulkProvisioningDialog(selected_devices, self.server_port, self)
        dialog.exec_()
        
        # Refresh the device list after bulk provisioning
        self.refresh_device_list()
    
    def refresh_device_list(self):
        """Refresh the device list from the database"""
        try:
            conn = sqlite3.connect("C:/Auto/Database/Auto.db")
            cursor = conn.cursor()
            
            # Clear the current device list
            self.devices = []
            self.device_table.setRowCount(0)
            
            # Get all devices from the database
            cursor.execute("SELECT ip_address, mac_address, extension, manufacturer, last_updated FROM devices ORDER BY last_updated DESC")
            devices = cursor.fetchall()
            
            conn.close()
            
            # Add devices to the list
            for device in devices:
                device_data = {
                    'ip': device[0],
                    'mac': device[1],
                    'extension': device[2],
                    'manufacturer': device[3],
                    'last_updated': device[4]
                }
                self.devices.append(device_data)
                self.add_device_to_table(device_data)
                
        except Exception as e:
            print(f"Error refreshing device list: {e}")
    
    def add_device_to_table(self, device_data):
        """Add a device to the table"""
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        # Add checkbox for selection
        checkbox = QCheckBox()
        checkbox_widget = QWidget()
        checkbox_layout = QHBoxLayout(checkbox_widget)
        checkbox_layout.addWidget(checkbox)
        checkbox_layout.setAlignment(Qt.AlignCenter)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)
        self.device_table.setCellWidget(row, 0, checkbox_widget)
        
        # IP Address
        item = QTableWidgetItem(device_data['ip'])
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 1, item)
        
        # MAC Address
        item = QTableWidgetItem(device_data['mac'])
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 2, item)
        
        # Extension
        item = QTableWidgetItem(device_data['extension'])
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 3, item)
        
        # Manufacturer
        item = QTableWidgetItem(device_data['manufacturer'])
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 4, item)
        
        # Last Updated
        item = QTableWidgetItem(device_data['last_updated'])
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 5, item)
        
        # Create action button
        action_widget = QWidget()
        action_layout = QHBoxLayout(action_widget)
       
        action_layout.setContentsMargins(2, 2, 2, 2)
        action_layout.setSpacing(5)
        provision_btn = QPushButton("Provision")
        
        provision_btn.setStyleSheet("""
    QPushButton {
        background-color: #f0f0f0;
        color: black;
        border: 1px solid #999;
        padding: 8px 15px;
        border-radius: 0px;
    }
    QPushButton:hover {
        background-color: #cce7ff; 
        border: 1px solid #0078d7;
    }
        """)
        provision_btn.clicked.connect(lambda _, r=row: self.provision_device(r))
        
        action_layout.addWidget(provision_btn)
        action_layout.addStretch()
        
        self.device_table.setCellWidget(row, 6, action_widget)

    def auto_detect_ip_range(self):
        """Auto-detect and fill the IP range field"""
        try:
            # Get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to a public DNS server to determine the active network interface
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Parse the IP address
            ip_parts = local_ip.split('.')
            
            # Create a network range (assuming a /24 subnet)
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            # Set the IP range
            self.ip_range_input.setText(network_range)
            
        except Exception as e:
            print(f"Error auto-detecting IP range: {e}")
            # Use a default range
            self.ip_range_input.setText("192.168.1.0/24")
    
    def on_server_log(self, message):
        """Handle server log message"""
        self.log_viewer.add_log(message)
    
    def show_logs(self):
        """Show the log viewer dialog"""
        self.log_viewer.exec_()
    
    DB_PATH = "C:/Auto/Database/Auto.db"
    def get_all_brands(self):
        """Retrieve all brands from the database."""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, mac_address FROM brands ORDER BY name")
        brands = cursor.fetchall()
        conn.close()
        return brands
       
    def start_scan(self):
        """Start scanning the network - clear previous results first"""
        ip_range = self.ip_range_input.text().strip()
        if ip_range:
            # Clear previous scan results
            self.devices = []
            self.device_table.setRowCount(0)
            
            # Pass the checkbox state to the scanner
            scan_all_devices = self.scan_all_checkbox.isChecked()
            self.scanner = NetworkScanner(ip_range, scan_all_devices)
            self.scanner.device_found.connect(self.add_device)
            self.scanner.scan_complete.connect(self.scan_complete)
            self.scanner.start()
            self.status_label.setText("Scanning...")
            self.scan_btn.setEnabled(False)
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a valid IP range.")

    def scan_complete(self):
        self.status_label.setText(f"Scan complete. Found {len(self.devices)} devices.")
        self.scan_btn.setEnabled(True)
    
    def add_device(self, ip, mac, extension):
        # Get current timestamp for last updated
        current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        
        # Get manufacturer from MAC
        manufacturer = self.get_manufacturer(mac)
        
        # If extension is empty, try to auto-register an extension
        if not extension:
            extension = self.auto_register_extension(ip, mac, manufacturer)
        
        # Add the device to the table and the list
        device_data = {
            'ip': ip,
            'mac': mac,
            'extension': extension,
            'manufacturer': manufacturer,
            'last_updated': current_time
        }
        self.devices.append(device_data)
        
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        # Add checkbox for selection
        checkbox = QCheckBox()
        checkbox_widget = QWidget()
        checkbox_layout = QHBoxLayout(checkbox_widget)
        checkbox_layout.addWidget(checkbox)
        checkbox_layout.setAlignment(Qt.AlignCenter)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)
        self.device_table.setCellWidget(row, 0, checkbox_widget)
        
        # IP Address
        item = QTableWidgetItem(ip)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 1, item)
        
        # MAC Address
        item = QTableWidgetItem(mac)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 2, item)
        
        # Extension
        item = QTableWidgetItem(extension)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 3, item)
        
        # Manufacturer
        item = QTableWidgetItem(device_data['manufacturer'])
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 4, item)
        
        # Last Updated
        item = QTableWidgetItem(current_time)
        item.setTextAlignment(Qt.AlignCenter)
        self.device_table.setItem(row, 5, item)
        
        # Create action button
        action_widget = QWidget()
        action_layout = QHBoxLayout(action_widget)
       
        action_layout.setContentsMargins(2, 2, 2, 2)
        action_layout.setSpacing(5)
        provision_btn = QPushButton("Provision")
        provision_btn.setStyleSheet("""
    QPushButton {
        background-color: #f0f0f0;
        color: black;
        border: 1px solid #999;
        padding: 8px 15px;
        border-radius: 0px;
    }
    QPushButton:hover {
        background-color: #cce7ff; 
        border: 1px solid #0078d7;
    }
        """)
        provision_btn.clicked.connect(lambda _, r=row: self.provision_device(r))
        
        action_layout.addWidget(provision_btn)
        action_layout.addStretch()
        
        self.device_table.setCellWidget(row, 6, action_widget)
    
    def auto_register_extension(self, ip, mac, manufacturer):
        """Automatically register an extension for a discovered device"""
        try:
            # Check if device already exists in database
            conn = sqlite3.connect("C:/Auto/Database/Auto.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT extension FROM devices WHERE mac_address = ?", (mac,))
            device = cursor.fetchone()
            
            if device and device[0]:
                # Device exists with extension
                conn.close()
                return device[0]
            
            # Find an available extension
            cursor.execute("SELECT display_name FROM extension_list WHERE display_name NOT IN (SELECT extension FROM devices WHERE extension IS NOT NULL) ORDER BY display_name LIMIT 1")
            available_ext = cursor.fetchone()
            
            if available_ext:
                extension = available_ext[0]
                
                # Register the extension to this device
                if device:
                    # Update existing device
                    cursor.execute(
                        "UPDATE devices SET extension = ?, last_updated = ? WHERE mac_address = ?",
                        (extension, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), mac)
                    )
                else:
                    # Insert new device
                    cursor.execute(
                        "INSERT INTO devices (ip_address, mac_address, manufacturer, extension, last_updated) VALUES (?, ?,?,?,?)",
                        (ip, mac, manufacturer, extension, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    )
                
                conn.commit()
                conn.close()
                
                # Log the auto-registration
                self.log_viewer.add_log(f"Auto-registered extension {extension} to device {ip} ({mac})")
                
                return extension
            else:
                conn.close()
                return "No Extension"
                
        except Exception as e:
            print(f"Error auto-registering extension: {e}")
            return "Error"
 
    def filter_table(self):
        filter_text = self.search_input.text().lower()
        for row in range(self.device_table.rowCount()):
            ip_item = self.device_table.item(row, 1)
            mac_item = self.device_table.item(row, 2)
            extension_item = self.device_table.item(row, 3)
            manufacturer_item = self.device_table.item(row, 4)
            last_updated_item = self.device_table.item(row, 5)
            
            matched = False
            if ip_item and filter_text in ip_item.text().lower():
                matched = True
            elif mac_item and filter_text in mac_item.text().lower():
                matched = True
            elif extension_item and filter_text in extension_item.text().lower():
                matched = True
            elif manufacturer_item and filter_text in manufacturer_item.text().lower():
                matched = True
            elif last_updated_item and filter_text in last_updated_item.text().lower():
                matched = True
                
            self.device_table.setRowHidden(row, not matched)
   
    def provision_device(self, row):
        """Open the provisioning dialog for the selected device"""
        device = self.devices[row]
        dialog = ProvisioningDialog(device, self.server_port, self)
        dialog.exec_()

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
            
            # If not found in database, check against known OUIs
            if mac_prefix in MAC_OUI_DATABASE:
                return MAC_OUI_DATABASE[mac_prefix]
        
        return 'Unknown Manufacturer'





if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    device_page = ProvisionPage()
    device_page.show()
    sys.exit(app.exec_())

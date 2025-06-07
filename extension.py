import sys
import os
import threading
import time
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QFormLayout, 
                            QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, 
                            QLabel, QHBoxLayout, QDialog, QDialogButtonBox, 
                            QFileDialog, QMessageBox, QProgressBar, QComboBox)
from PyQt5.QtCore import QDateTime, pyqtSignal, QObject, Qt
import openpyxl  # Library to read Excel files

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHBoxLayout, QLabel,
    QMessageBox, QFileDialog, QProgressBar, QHeaderView,
    QSizePolicy, QDialog
)
from PyQt5.QtCore import Qt
import threading
import time
import openpyxl

# Import our custom modules
from database import DatabaseManager
import logging
import socket
import re
import uuid
import hashlib
import time

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
class SIPClient:
    """Improved SIP client for registering extensions"""
    def __init__(self, username, password, domain, display_name=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.display_name = display_name or username
        self.registered = False
        self.call_id = str(uuid.uuid4())
        self.sip_port = 5060
        self.branch = self.generate_branch()
        self.tag = self.generate_tag()
        
    def register(self):
        """Register the SIP extension with the server"""
        try:
            logging.info(f"Attempting to register {self.username}@{self.domain}...")
            
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)  # Increase timeout to 10 seconds
            
            # Prepare the REGISTER request
            register_msg = self.create_register_request()
            
            # Resolve domain to IP if needed
            try:
                server_ip = socket.gethostbyname(self.domain)
            except socket.gaierror:
                server_ip = self.domain
                
            logging.info(f"Connecting to SIP server at {server_ip}:{self.sip_port}")
            
            # Send the request to the SIP server
            sock.sendto(register_msg.encode(), (server_ip, self.sip_port))
            
            # Wait for a response
            try:
                data, addr = sock.recvfrom(4096)
                response = data.decode()
                logging.info(f"Received response: {response.splitlines()[0]}")
                
                # Check if registration was successful (200 OK)
                if "SIP/2.0 200" in response:
                    self.registered = True
                    sock.close()
                    return True, "Registration successful"
                elif "SIP/2.0 401" in response or "SIP/2.0 407" in response:
                    # Extract nonce for authentication
                    nonce_match = re.search(r'nonce="([^"]+)"', response)
                    realm_match = re.search(r'realm="([^"]+)"', response)
                    
                    if nonce_match and realm_match:
                        nonce = nonce_match.group(1)
                        realm = realm_match.group(1)
                        
                        logging.info(f"Authentication required. Nonce: {nonce}, Realm: {realm}")
                        
                        # Create authenticated request
                        auth_request = self.create_authenticated_request(nonce, realm)
                        
                        # Send authenticated request
                        logging.info("Sending authenticated request...")
                        sock.sendto(auth_request.encode(), (server_ip, self.sip_port))
                        
                        # Wait for response to authenticated request
                        data, addr = sock.recvfrom(4096)
                        auth_response = data.decode()
                        logging.info(f"Auth response: {auth_response.splitlines()[0]}")
                        
                        if "SIP/2.0 200" in auth_response:
                            self.registered = True
                            sock.close()
                            return True, "Registration successful with authentication"
                    
                    sock.close()
                    return False, "Authentication failed"
                else:
                    sock.close()
                    return False, f"Registration failed: {response.splitlines()[0]}"
                    
            except socket.timeout:
                sock.close()
                return False, "Connection timed out waiting for server response"
                
        except socket.timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def create_register_request(self):
        """Create a SIP REGISTER request"""
        return (
            f"REGISTER sip:{self.domain} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {self.domain}:{self.sip_port};branch=z9hG4bK{self.branch}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: \"{self.display_name}\" <sip:{self.username}@{self.domain}>;tag={self.tag}\r\n"
            f"To: <sip:{self.username}@{self.domain}>\r\n"
            f"Call-ID: {self.call_id}\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Contact: <sip:{self.username}@{self.domain}:{self.sip_port}>\r\n"
            f"Expires: 3600\r\n"
            f"User-Agent: PyQtSIPPhone/1.0\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
    
    def create_authenticated_request(self, nonce, realm):
        """Create an authenticated SIP REGISTER request"""
        # Digest authentication
        ha1 = hashlib.md5(f"{self.username}:{realm}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"REGISTER:sip:{self.domain}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        
        return (
            f"REGISTER sip:{self.domain} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {self.domain}:{self.sip_port};branch=z9hG4bK{self.branch}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: \"{self.display_name}\" <sip:{self.username}@{self.domain}>;tag={self.tag}\r\n"
            f"To: <sip:{self.username}@{self.domain}>\r\n"
            f"Call-ID: {self.call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{self.username}@{self.domain}:{self.sip_port}>\r\n"
            f"Expires: 3600\r\n"
            f"User-Agent: PyQtSIPPhone/1.0\r\n"
            f"Authorization: Digest username=\"{self.username}\", realm=\"{realm}\", "
            f"nonce=\"{nonce}\", uri=\"sip:{self.domain}\", response=\"{response}\", algorithm=MD5\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
    
    def generate_branch(self):
        """Generate a branch parameter for Via header"""
        import random
        return ''.join(random.choice('0123456789abcdef') for _ in range(10))
    
    def generate_tag(self):
        """Generate a tag parameter for From header"""
        import random
        return ''.join(random.choice('0123456789abcdef') for _ in range(8))
    
class SignalEmitter(QObject):
    """Class to emit signals for thread-safe UI updates"""
    update_status = pyqtSignal(int, str)
    registration_complete = pyqtSignal()


class ExtensionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.db_manager = DatabaseManager()
        self.signal_emitter = SignalEmitter()
        self.signal_emitter.update_status.connect(self.update_extension_status)
        self.signal_emitter.registration_complete.connect(self.registration_process_complete)
        self.initUI()
        self.load_extensions_from_db()
    
    def initUI(self):
        self.setWindowTitle("Softphone Extension Manager")
        

        main_layout = QVBoxLayout()
        form_layout = QFormLayout()

        self.display_name_input = QLineEdit(self)
        self.username_input = QLineEdit(self)
        self.password_input = QLineEdit(self)
        self.domain_input = QLineEdit(self)

        form_layout.addRow("Display Name:", self.display_name_input)
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)
        form_layout.addRow("Domain:", self.domain_input)
        
        add_button = QPushButton("Add Extension", self)
        add_button.setFixedSize(150, 40)
        add_button.clicked.connect(self.add_extension)
        

        upload_button = QPushButton("Upload Extension", self)
        upload_button.setFixedSize(150, 40)
        upload_button.clicked.connect(self.upload_extension)
        
        register_all_button = QPushButton("Register All", self)
        register_all_button.setFixedSize(150, 40)
        register_all_button.clicked.connect(self.register_all_extensions)
        
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setVisible(False)

        self.extension_table = QTableWidget(self)
        self.extension_table.setRowCount(0)
        self.extension_table.setColumnCount(6)
        self.extension_table.setHorizontalHeaderLabels(
            ["Display Name", "Username", "Password", "Domain", "Status", "Action"]
        )

        # Make table take full width
        self.extension_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        header = self.extension_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(add_button)
        button_layout.addWidget(upload_button)
        button_layout.addWidget(register_all_button)
        main_layout.addLayout(form_layout)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.progress_bar)
       
        main_layout.addWidget(self.extension_table)

        self.setLayout(main_layout)

    def add_extension(self):
        display_name = self.display_name_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        domain = self.domain_input.text()

        if not display_name or not username or not password or not domain:
            QMessageBox.warning(self, "Input Error", "Please fill all fields.")
            return

        if self.db_manager.add_extension(display_name, username, password, domain):
            self.add_extension_to_table(display_name, username, password, domain, "Not Registered")
            self.display_name_input.clear()
            self.username_input.clear()
            self.password_input.clear()
            self.domain_input.clear()
            
            reply = QMessageBox.question(self, 'Register Extension', 
                                         'Do you want to register this extension now?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if reply == QMessageBox.Yes:
                row = self.extension_table.rowCount() - 1
                self.register_extension(row)
        else:
            QMessageBox.critical(self, "Database Error", "Failed to add extension to database.")

    def add_extension_to_table(self, display_name, username, password, domain, status):
        row_position = self.extension_table.rowCount()
        self.extension_table.insertRow(row_position)

        self.extension_table.setItem(row_position, 0, QTableWidgetItem(display_name))
        self.extension_table.setItem(row_position, 1, QTableWidgetItem(username))
        self.extension_table.setItem(row_position, 2, QTableWidgetItem(password))
        self.extension_table.setItem(row_position, 3, QTableWidgetItem(domain))

        status_item = QTableWidgetItem(status)
        if status == "Registered":
            status_item.setText("Register")
        elif status == "Failed":
            status_item.setText("Failed")
        else:
            status_item.setText("Process")

        self.extension_table.setItem(row_position, 4, status_item)

        register_button = QPushButton("Register")
        register_button.setToolTip("Register Extension")
        
        edit_button = QPushButton("Edit")
        edit_button.setToolTip("Edit Extension")
       
        delete_button = QPushButton("Delete")
        delete_button.setToolTip("Delete Extension")
        

        register_button.clicked.connect(lambda: self.register_extension(row_position))
        edit_button.clicked.connect(lambda: self.open_edit_dialog(row_position))
        delete_button.clicked.connect(lambda: self.delete_extension(row_position))

        button_layout = QHBoxLayout()
        button_layout.addWidget(register_button)
        button_layout.addWidget(edit_button)
        button_layout.addWidget(delete_button)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(2)
        

        widget = QWidget()
        widget.setLayout(button_layout)
        self.extension_table.setCellWidget(row_position, 5, widget)

    def upload_extension(self):
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getOpenFileName(self, "Open Extension File", "", "Excel Files (*.xls *.xlsx)")
        if not file_path:
            return

        try:
            workbook = openpyxl.load_workbook(file_path)
            sheet = workbook.active
            for row in sheet.iter_rows(min_row=2, values_only=True):
                if len(row) >= 4:
                    display_name, username, password, domain = row[0:4]
                    if self.db_manager.add_extension(display_name, username, password, domain):
                        self.add_extension_to_table(display_name, username, password, domain, "Not Registered")
            reply = QMessageBox.question(self, 'Register Extensions', 
                                         'Do you want to register all uploaded extensions now?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if reply == QMessageBox.Yes:
                self.register_all_extensions()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to upload file: {e}")

    def register_extension(self, row):
        display_name = self.extension_table.item(row, 0).text()
        username = self.extension_table.item(row, 1).text()
        password = self.extension_table.item(row, 2).text()
        domain = self.extension_table.item(row, 3).text()

        status_item = QTableWidgetItem("Registering...")
        status_item.setText("Registering")
        self.extension_table.setItem(row, 4, status_item)
        QApplication.processEvents()

        threading.Thread(target=self.register_extension_thread, 
                         args=(row, display_name, username, password, domain)).start()

    def register_extension_thread(self, row, display_name, username, password, domain):
        sip_client = SIPClient(username, password, domain, display_name)
        success, message = sip_client.register()
        status = "Registered" if success else "Failed"
        self.db_manager.update_extension_status(username, status)
        self.signal_emitter.update_status.emit(row, status)

    def update_extension_status(self, row, status):
        status_item = QTableWidgetItem(status)
        if status == "Registered":
            status_item.setText("Register")
        else:
            status_item.setText("Failed")
        self.extension_table.setItem(row, 4, status_item)

    def register_all_extensions(self):
        row_count = self.extension_table.rowCount()
        if row_count == 0:
            QMessageBox.information(self, "No Extensions", "There are no extensions to register.")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, row_count)
        self.progress_bar.setValue(0)

        threading.Thread(target=self.register_all_thread, args=(row_count,)).start()

    def register_all_thread(self, row_count):
        for row in range(row_count):
            display_name = self.extension_table.item(row, 0).text()
            username = self.extension_table.item(row, 1).text()
            password = self.extension_table.item(row, 2).text()
            domain = self.extension_table.item(row, 3).text()

            self.signal_emitter.update_status.emit(row, "Registering...")

            sip_client = SIPClient(username, password, domain, display_name)
            success, message = sip_client.register()
            status = "Registered" if success else "Failed"
            self.db_manager.update_extension_status(username, status)
            self.signal_emitter.update_status.emit(row, status)

            self.progress_bar.setValue(row + 1)
            time.sleep(0.5)

        self.signal_emitter.registration_complete.emit()

    def registration_process_complete(self):
        self.progress_bar.setVisible(False)
        QMessageBox.information(self, "Registration Complete", "All extensions have been processed.")

    def open_edit_dialog(self, row):
        dialog = EditDialog(self, row)
        if dialog.exec_() == QDialog.Accepted:
            username = self.extension_table.item(row, 1).text()
            display_name = self.extension_table.item(row, 0).text()
            password = self.extension_table.item(row, 2).text()
            domain = self.extension_table.item(row, 3).text()
            status = self.extension_table.item(row, 4).text()
            self.db_manager.add_extension(display_name, username, password, domain, status)

    def delete_extension(self, row):
        reply = QMessageBox.question(self, 'Confirmation', 'Are you sure you want to delete this extension?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            username = self.extension_table.item(row, 1).text()
            if self.db_manager.delete_extension(username):
                self.extension_table.removeRow(row)
            else:
                QMessageBox.critical(self, "Database Error", "Failed to delete extension from database.")

    def load_extensions_from_db(self):
        extensions = self.db_manager.get_all_extensions()
        for ext in extensions:
            display_name, username, password, domain, status, _ = ext
            self.add_extension_to_table(display_name, username, password, domain, status)

class EditDialog(QDialog):
    def __init__(self, parent, row):
        super().__init__(parent)

        self.row = row  # The row to edit
        self.setWindowTitle("Edit Extension")
        self.setMinimumWidth(300)

        # Create form layout for editing
        dialog_layout = QVBoxLayout()
        form_layout = QFormLayout()

        # Fields for editing
        self.display_name_input = QLineEdit(self)
        self.username_input = QLineEdit(self)
        self.password_input = QLineEdit(self)
        self.domain_input = QLineEdit(self)

        # Populate fields with current values from the table
        self.display_name_input.setText(parent.extension_table.item(row, 0).text())
        self.username_input.setText(parent.extension_table.item(row, 1).text())
        self.password_input.setText(parent.extension_table.item(row, 2).text())
        self.domain_input.setText(parent.extension_table.item(row, 3).text())

        # Add the form fields to the dialog layout
        form_layout.addRow("Display Name:", self.display_name_input)
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)
        form_layout.addRow("Domain:", self.domain_input)
        
        dialog_layout.addLayout(form_layout)

        # Add buttons to the dialog
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        dialog_layout.addWidget(button_box)

        # Connect the Save button to the save_edit method
        button_box.accepted.connect(self.save_edit)
        button_box.rejected.connect(self.reject)

        # Set the dialog layout
        self.setLayout(dialog_layout)

    def save_edit(self):
        # Save the changes to the table
        parent = self.parent()
        parent.extension_table.setItem(self.row, 0, QTableWidgetItem(self.display_name_input.text()))
        parent.extension_table.setItem(self.row, 1, QTableWidgetItem(self.username_input.text()))
        parent.extension_table.setItem(self.row, 2, QTableWidgetItem(self.password_input.text()))
        parent.extension_table.setItem(self.row, 3, QTableWidgetItem(self.domain_input.text()))
        
        # Reset status to "Not Registered"
        status_item = QTableWidgetItem("Not Registered")
        status_item.setText("Not Register")
        parent.extension_table.setItem(self.row, 4, status_item)
        
        self.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ExtensionApp()
    ex.show()
    sys.exit(app.exec_())
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QDialog, QFormLayout, QMessageBox, QGroupBox
)
from PyQt5.QtCore import Qt
from database import Database

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

class AddBrandDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Manufacturer")
        self.setMinimumWidth(400)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QFormLayout()
        
        self.name_input = QLineEdit()
        layout.addRow("Display Name:", self.name_input)
        
        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("e.g., 00:11:22:33:44:55")
        layout.addRow("MAC Address:", self.mac_input)
        
        button_layout = QHBoxLayout()
        self.submit_btn = QPushButton("Submit")
        self.submit_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.submit_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addRow("", button_layout)
        
        self.setLayout(layout)
    
    def get_data(self):
        return {
            "name": self.name_input.text().strip(),
            "mac_address": self.mac_input.text().strip()
        }

class EditBrandDialog(AddBrandDialog):
    def __init__(self, brand_name, mac_address, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Manufacturer")
        self.name_input.setText(brand_name)
        self.mac_input.setText(mac_address)

class BrandsPage(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Manufacturers Management")
        self.setGeometry(100, 100, 1000, 600)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        form_group = QGroupBox()
        form_layout = QVBoxLayout()
        
        input_layout = QFormLayout()
        self.display_name_input = QLineEdit()
        input_layout.addRow("Display Name:", self.display_name_input)
        
        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("00:11:22:33:44:55")
        input_layout.addRow("MAC Address:", self.mac_input)
        
        form_layout.addLayout(input_layout)
        
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        self.add_btn = QPushButton("Add Manufacturer")
        self.add_btn.setFixedSize(150, 40)
        self.add_btn.clicked.connect(self.add_brand)
        buttons_layout.addWidget(self.add_btn)
        
        form_layout.addLayout(buttons_layout)
        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)
        
        table_group = QGroupBox("Registered Manufacturers")
        table_layout = QVBoxLayout()
        
        self.brands_table = QTableWidget()
        self.brands_table.setColumnCount(3)
        self.brands_table.setHorizontalHeaderLabels(["Display Name", "MAC Address", "Action"])
        self.brands_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.brands_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.brands_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.brands_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.brands_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.brands_table.setSelectionMode(QTableWidget.SingleSelection)
        
        table_layout.addWidget(self.brands_table)
        table_group.setLayout(table_layout)
        main_layout.addWidget(table_group)
        
        self.refresh_brands()
    
    def refresh_brands(self):
        self.brands_table.setRowCount(0)
        brands = self.db.get_all_brands()
        
        for row, (brand_id, brand_name, mac_address) in enumerate(brands):
            self.brands_table.insertRow(row)
            self.brands_table.setItem(row, 0, QTableWidgetItem(brand_name))
            self.brands_table.setItem(row, 1, QTableWidgetItem(mac_address))
            
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0, 0, 0, 0)
            
            edit_btn = QPushButton("Edit")
            edit_btn.clicked.connect(lambda _, b_id=brand_id, b_name=brand_name, mac=mac_address: 
                                     self.edit_brand(b_id, b_name, mac))
            
            delete_btn = QPushButton("Delete")
            delete_btn.clicked.connect(lambda _, b_id=brand_id, b_name=brand_name: 
                                       self.delete_brand(b_id, b_name))
            
            action_layout.addWidget(edit_btn)
            action_layout.addWidget(delete_btn)
            action_layout.setSpacing(5)
            self.brands_table.setCellWidget(row, 2, action_widget)
    
    def add_brand(self):
        name = self.display_name_input.text().strip()
        mac_address = self.mac_input.text().strip()
        
        if not name or not mac_address:
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return
        
        brand_id = self.db.add_brand(name, mac_address)
        if brand_id:
            self.display_name_input.clear()
            self.mac_input.clear()
            self.refresh_brands()
        else:
            QMessageBox.warning(self, "Add Error", "Failed to add manufacturer. Name might be duplicate.")
    
    def edit_brand(self, brand_id, brand_name, mac_address):
        dialog = EditBrandDialog(brand_name, mac_address, self)
        if dialog.exec_():
            data = dialog.get_data()
            if not data["name"] or not data["mac_address"]:
                QMessageBox.warning(self, "Input Error", "All fields are required.")
                return
            
            if self.db.update_brand(brand_id, data["name"], data["mac_address"]):
                self.refresh_brands()
            else:
                QMessageBox.warning(self, "Update Error", "Failed to update manufacturer. Name might be duplicate.")
    
    def delete_brand(self, brand_id, brand_name):
        reply = QMessageBox.question(self, "Confirm Deletion", 
                                     f"Are you sure you want to delete {brand_name}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.db.delete_brand(brand_id):
                self.refresh_brands()
            else:
                QMessageBox.warning(self, "Delete Error", "Failed to delete manufacturer.")

def main():
    app = QApplication(sys.argv)
    window = BrandsPage()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

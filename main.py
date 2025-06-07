import sys, os,logging

# Create logs directory before any imports
def create_logs_directory():
    """Create the logs directory if it doesn't exist"""
    logs_dir = r"C:\Auto\Logs"
    try:
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
            logging.info(f"Created logs directory at {logs_dir}")
        else:
            logging.info(f"Logs directory already exists at {logs_dir}")
    except Exception as e:
        logging.info(f"Error creating logs directory: {e}")

# Create the logs directory before importing any modules
create_logs_directory()

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout,
    QMainWindow, QAction, QFrame, QMessageBox, QSplitter, QScrollArea
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
import sys,os

# Import your page classes
from device import ProvisionPage
from brands import BrandsPage
from refresh import RefreshPage
from extension import ExtensionApp
from tr069 import MainWindow
from database import Database,DatabaseManager
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


class HelpPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumWidth(230)
        self.setMaximumWidth(240)  # 20% of 1300px minimum width
        db = Database()
        db=DatabaseManager()

        # Set background color and border
        self.setStyleSheet("""
            background-color: white;
           
        """)
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Help header
        self.help_header = QLabel("Help")
        self.help_header.setStyleSheet("""
           
            font-weight: bold;
            padding: 10px;
            font-size: 14px;
        """)
        self.help_header.setAlignment(Qt.AlignCenter)
        
        # Scroll area for help content
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        
        self.help_content = QWidget()
        self.help_layout = QVBoxLayout(self.help_content)
        self.help_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.help_content)
        
        self.layout.addWidget(self.help_header)
        self.layout.addWidget(self.scroll_area)
        
        # Default help content
        self.update_help("default")
    
    def update_help(self, page_name):
        # Clear existing content
        while self.help_layout.count():
            item = self.help_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        
        help_sections = self.get_help_content(page_name)
        
        for section in help_sections:
            # Section title
            title = QLabel(section["title"])
            title.setStyleSheet("""
                font-weight: bold;
                color: #2c3e50;
                font-size: 16px;
                padding-top: 10px;
                padding-bottom: 5px;
            """)
            
            # Section content
            content = QLabel(section["content"])
            content.setWordWrap(True)
            content.setStyleSheet("""
                color: #333333;
                font-size: 15px;
              
            """)
            
            self.help_layout.addWidget(title)
            self.help_layout.addWidget(content)
            # self.help_layout.addWidget(separator)
        
        # Add helpdesk information at the bottom
        helpdesk = QLabel("HelpDesk:")
        helpdesk.setStyleSheet("""
            font-weight: bold;
            color: #2c3e50;
            font-size: 15px;
            padding-top: 15px;
        """)
        
        contact = QLabel("+91.8587.000.818\n +91.7777.022.022\n www.nerontech.in")
        contact.setStyleSheet("""
            color: #333333;
            font-size: 15px;
         
        """)
        
        self.help_layout.addWidget(helpdesk)
        self.help_layout.addWidget(contact)
        self.help_layout.addStretch()
    
    def get_help_content(self, page_name):
        help_content = {
            "default": [
                {
                    "title": "Welcome to Auto Provisioning App",
                    "content": "Select a menu option to get started. Help content will be displayed here based on the selected page."
                }
            ],
            "device": [
                {
                    "title": "Provision Information:",
                    "content": "This provision allow Extension Update. Enter the device details and click on 'Provision' to add the device to the system."
                },
                {
                    "title": "Neron Provisining Url",
                    "content": "{localhost}:{port}/configs/device_mac.cfg"
                },
                {
                    "title": "Yealink Provisining Url",
                    "content": "{localhost}:{port}/configs"
                },
                {
                    "title": "Fanvil Provisining Url",
                    "content": "{localhost}:{port}/configs"
                },
                {
                    "title": "Grandstream Url",
                    "content": "{localhost}:{port}/configs"
                },
                {
                    "title": "Alcaltel Url",
                    "content": "{localhost}:{port}/configs"
                },
                
            ],
            "brands": [
                {
                    "title": "Manufacturer Information:",
                    "content": "This page shows all supported device manufacturers and their models."
                },
                {
                    "title": "Adding New Manufacturer:",
                    "content": "To add a new manufacturer, click on the 'Add' button and fill in the required details."
                },
                {
                    "title": "Model Configuration:",
                    "content": "Each manufacturer can have multiple models. Select a manufacturer to view and configure its models."
                }
            ],
            "refresh": [
                {
                    "title": "Refresh Information:",
                    "content": "This page allows you to scan the network for devices and refresh their status."
                },
                {
                    "title": "Scan Network:",
                    "content": "Click on 'Scan' to discover new devices on the network."
                },
                {
                    "title": "Refresh Status:",
                    "content": "Click on 'Refresh' to update the status of all devices."
                }
            ],
            "extension": [
                {
                    "title": "Extension Management:",
                    "content": "This page allows you to manage phone extensions and their configurations."
                },
                {
                    "title": "Adding Extensions:",
                    "content": "To add a new extension, click on the 'Add' button and enter the extension details."
                },
                {
                    "title": "Extension Status:",
                    "content": "View the status of all extensions, including registration status and assigned devices."
                }
            ],
            "tr069": [
                {
                    "title": "TR-069 Configuration:",
                    "content": "This page allows you to configure TR-069 settings for remote device management."
                },
                {
                    "title": "ACS Settings:",
                    "content": "Configure Auto Configuration Server (ACS) settings including URL, username, and password."
                },
                {
                    "title": "TR069 ACS Url",
                    "content": "http://{localhost}:7547"
                },
                {
                    "title": "TR069 Authentication",
                    "content": "Username : admin \n Password : admin "
                },
                {
                    "title": "Device Connection",
                    "content": "First Apply ACS URL and then username and password update to make a successfull connectection"
                }
            ]
        }
        
        return help_content.get(page_name, help_content["default"])

class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Auto Provisioning Application')
        # self.setWindowIcon(QIcon("neron-favicon.svg"))
        self.setWindowIcon(QIcon(self.resource_path("neron-favicon.svg")))
        self.setMinimumSize(1500, 850)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QMenuBar {
                background-color: #2c3e50;
                color: white;
            }
            QMenuBar::item {
                spacing: 3px;
                padding: 5px 15px;
                background: transparent;
                border-radius: 0px;
            }
            QMenuBar::item:selected {
                background: #2f4857;
            }
            QMenu {
                background-color: #ffffff;
                border: 1px solid #ccc;
            }
            QMenu::item {
                padding: 6px 25px;
            }
            QMenu::item:selected {
                background-color: #cce7ff;
            }
            QSplitter::handle {
                background-color: white;
            }
        """)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Create content area with splitter
        self.content_container = QWidget()
        self.content_layout = QHBoxLayout(self.content_container)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)
        
        # Create splitter for main content and help panel
        self.splitter = QSplitter(Qt.Horizontal)
        
        # Main content area
        self.page_container = QWidget()
        self.page_layout = QVBoxLayout(self.page_container)
        self.page_layout.setContentsMargins(0, 0, 0, 0)
        self.page_layout.setSpacing(0)
        
        # Help panel
        self.help_panel = HelpPanel()
        
        # Add widgets to splitter
        self.splitter.addWidget(self.page_container)
        self.splitter.addWidget(self.help_panel)
        
        # Set initial sizes (80% main content, 20% help panel)
        self.splitter.setSizes([int(self.width() * 0.8), int(self.width() * 0.2)])
        
        self.content_layout.addWidget(self.splitter)
        self.main_layout.addWidget(self.content_container)

        self.pages = {}

        self.create_menu_bar()

        self.footer = self.create_footer()
        self.main_layout.addWidget(self.footer)

        self.refresh_page = RefreshPage()
        self.pages["refresh"] = self.refresh_page

        self.switch_page("device")

    def create_menu_bar(self):
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("File")

        scan_action = QAction("Scan", self)
        scan_action.triggered.connect(lambda: self.switch_page("refresh"))

        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.trigger_refresh)

        save_action = QAction("Save", self)
        save_action.triggered.connect(lambda: QMessageBox.information(self, "Save", "Save action triggered"))

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)

        file_menu.addAction(scan_action)
        file_menu.addAction(refresh_action)
        file_menu.addAction(save_action)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        device_action = QAction("Provision", self)
        device_action.triggered.connect(lambda: self.switch_page("device"))
        menu_bar.addAction(device_action)

        brands_action = QAction("Manufacturer", self)
        brands_action.triggered.connect(lambda: self.switch_page("brands"))
        menu_bar.addAction(brands_action)

        extension_action = QAction("Extension", self)
        extension_action.triggered.connect(lambda: self.switch_page("extension"))
        menu_bar.addAction(extension_action)

        tr069_action = QAction("TR-069", self)
        tr069_action.triggered.connect(lambda: self.switch_page("tr069"))
        menu_bar.addAction(tr069_action)

        help_menu = menu_bar.addMenu("Help")

        add_ext_action = QAction("Add Extension", self)
        add_ext_action.triggered.connect(lambda: QMessageBox.information(self, "Add Extension", "Feature coming soon!"))

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about_dialog)

        feedback_action = QAction("Feedback", self)
        feedback_action.triggered.connect(lambda: QMessageBox.information(self, "Feedback", "Send feedback to support@neron.in"))

        help_menu.addAction(add_ext_action)
        help_menu.addAction(about_action)
        help_menu.addAction(feedback_action)

    def switch_page(self, page_name):
        # Clear current page
        while self.page_layout.count():
            item = self.page_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)

        # Create page if it doesn't exist
        if page_name not in self.pages:
            if page_name == "device":
                self.pages[page_name] = ProvisionPage(self)
            elif page_name == "brands":
                self.pages[page_name] = BrandsPage()
            elif page_name == "tr069":
                self.pages[page_name] = MainWindow()
            elif page_name == "extension":
                self.pages[page_name] = ExtensionApp()
            elif page_name == "dashboard":
                self.pages[page_name] = self.create_placeholder("Dashboard Page")
            else:
                self.pages[page_name] = self.create_placeholder("Page not found")

        # Add page to layout
        self.page_layout.addWidget(self.pages[page_name])
        
        # Update help panel content
        self.help_panel.update_help(page_name)

    def trigger_refresh(self):
        if hasattr(self.refresh_page, 'refresh_btn'):
            self.refresh_page.refresh_btn.click()

    def show_about_dialog(self):
        QMessageBox.information(
            self,
            "About",
            "Auto Provisioning App v1.0\nDeveloped by Neron Informatic Pvt. Ltd."
        )
    
    def create_footer(self):
        footer = QFrame()
        footer.setFixedHeight(40)
        footer.setStyleSheet("background-color: #2c3e50; color: white;")

        layout = QHBoxLayout(footer)
        layout.setContentsMargins(10, 0, 10, 0)
        layout.setSpacing(0)

        # Left-aligned, vertically centered label
        copyright_label = QLabel(
            f"© {2025} Neron Informatic Pvt. Ltd. All rights reserved.")
        copyright_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)

        # Right-aligned, vertically centered label
        version_label = QLabel("version-1.0")
        version_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight)

        layout.addWidget(copyright_label)
        layout.addStretch(1)
        layout.addWidget(version_label)

        return footer
    @staticmethod
    def resource_path(relative_path):
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    def create_placeholder(self, text):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel(text)
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        return widget

def main():
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
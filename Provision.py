import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton
import database  # Import the database functions from the database module
from main import MainApp  # Import the MainApp from main.py
import logging

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.basicConfig(
    filename='C:/Auto/Database/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
class LoginApp(QWidget):
    def __init__(self):
        super().__init__()

        # Set window properties
        self.setWindowTitle('Login Application')
        self.setGeometry(500, 200, 300, 200)  # Increased window height to fit the status label

        # Create widgets
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)

        # Status label to show login status
        self.status_label = QLabel("")  # This will hold the login status message
        self.status_label.setStyleSheet("color: red;")  # Style the label with red color for error messages

        # Create layout
        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.status_label)  # Add the status label to the layout

        self.setLayout(layout)

        # Ensure the database is set up (first time or not)
        database.create_database()

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        # Try to validate login credentials
        if database.validate_login(username, password):
            self.status_label.setText("Login successful!")  # Update status label
            self.status_label.setStyleSheet("color: green;")  # Change text color to green for success
            self.open_main_app()  # Open the main application after login
        else:
            # Check if it's the first time running the app
            if database.is_first_time_login():
                self.create_user(username, password)
                self.status_label.setText("User created and logged in successfully!")  # Update status label
                self.status_label.setStyleSheet("color: green;")  # Change text color to green for success
                self.open_main_app()  # Open the main application after user creation
            else:
                self.status_label.setText("Invalid username or password!")  # Update status label
                self.status_label.setStyleSheet("color: red;")  # Set text color to red for error

    def create_user(self, username, password):
        """Creates a new user in the database"""
        database.create_user(username, password)

    def open_main_app(self):
        """Opens the Main Application after successful login"""
        self.close()  # Close the login window
        self.main_app = MainApp() 
         # Create the main app window
        self.main_app.show()  # Show the main app window
    

def main():
    app = QApplication(sys.argv)
    window = LoginApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

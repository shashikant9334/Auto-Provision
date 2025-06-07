import sqlite3
import os
from datetime import datetime
import logging
# Path to database file
DB_PATH = "C:/Auto/Database/Auto.db"

# Ensure the database directory exists
if not os.path.exists("C:/Auto/Database"):
    os.makedirs("C:/Auto/Database")

def create_database():
    """Creates a database and users table if not exists"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    logging.info("Database and table created.")


def create_user(username, password):
    """Creates a new user in the database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()
    logging.info(f"User '{username}' created.")


def validate_login(username, password):
    """Validates login credentials"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    result = c.fetchone()
    conn.close()
    return result is not None


def is_first_time_login():
    """Checks if any user exists in the database (first time login check)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users')
    result = c.fetchone()
    conn.close()
    return result is None

class Database:
    def __init__(self, db_file=DB_PATH):
        """Initialize database connection"""
        self.db_file = db_file
        self.create_tables()
    
    def create_tables(self):
        """Create necessary tables if they don't exist"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create brands table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS brands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL ,
            mac_address TEXT NOT NULL
        )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    extension TEXT,
    manufacturer TEXT,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);
''')
        # Update models table - change version to mac_address
        # First check if the table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='models'")
        if cursor.fetchone():
            # Check if we need to alter the table
            cursor.execute("PRAGMA table_info(models)")
            columns = [info[1] for info in cursor.fetchall()]
            
            if 'version' in columns and 'mac_address' not in columns:
                # Create a new table with the updated schema
                cursor.execute('''
                CREATE TABLE models_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    brand_id INTEGER NOT NULL,
                    model_name TEXT NOT NULL,
                    mac_address TEXT,
                    FOREIGN KEY (brand_id) REFERENCES brands (id) ON DELETE CASCADE
                )
                ''')
                
                # Copy data from old table to new table
                cursor.execute('''
                INSERT INTO models_new (id, brand_id, model_name, mac_address)
                SELECT id, brand_id, model_name, version FROM models
                ''')
                
                # Drop old table and rename new table
                cursor.execute("DROP TABLE models")
                cursor.execute("ALTER TABLE models_new RENAME TO models")
                
                logging.info("Updated models table schema: changed 'version' to 'mac_address'")
            elif 'mac_address' not in columns:
                # Just add the mac_address column if it doesn't exist
                cursor.execute("ALTER TABLE models ADD COLUMN mac_address TEXT")
                logging.info("Added 'mac_address' column to models table")
        else:
            # Create models table with mac_address instead of version
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand_id INTEGER NOT NULL,
                model_name TEXT NOT NULL,
                mac_address TEXT,
                FOREIGN KEY (brand_id) REFERENCES brands (id) ON DELETE CASCADE
            )
            ''')
        
        conn.commit()
        conn.close()
    
    def get_all_brands(self):
        """Retrieve all brands from the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, mac_address FROM brands ORDER BY name")
        brands = cursor.fetchall()
        conn.close()
        return brands
    
    def add_brand(self, name, mac_address):
        """Add a new brand to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO brands (name, mac_address) VALUES (?, ?)", 
                          (name, mac_address))
            conn.commit()
            brand_id = cursor.lastrowid
            conn.close()
            return brand_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    def update_brand(self, brand_id, name, mac_address):
        """Update an existing brand"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE brands SET name = ?, mac_address = ? WHERE id = ?", 
                          (name, mac_address, brand_id))
            conn.commit()
            success = cursor.rowcount > 0
            conn.close()
            return success
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def delete_brand(self, brand_id):
        """Delete a brand and all its models"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM brands WHERE id = ?", (brand_id,))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
    
    def get_models_by_brand(self, brand_id):
        """Get all models for a specific brand"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT m.id, m.model_name, b.mac_address, m.mac_address 
            FROM models m
            JOIN brands b ON m.brand_id = b.id
            WHERE m.brand_id = ?
        """, (brand_id,))
        models = cursor.fetchall()
        conn.close()
        return models
    
    def add_model(self, brand_id, model_name, mac_address):
        """Add a new model to a brand"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO models (brand_id, model_name, mac_address) 
            VALUES (?, ?, ?)
        """, (brand_id, model_name, mac_address))
        conn.commit()
        model_id = cursor.lastrowid
        conn.close()
        return model_id
    
    def update_model(self, model_id, model_name, mac_address):
        """Update an existing model"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE models 
            SET model_name = ?, mac_address = ? 
            WHERE id = ?
        """, (model_name, mac_address, model_id))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
    
    def delete_model(self, model_id):
        """Delete a model"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM models WHERE id = ?", (model_id,))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
    
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
    
    
    
    

class DatabaseManager:
    """Manages the SQLite database for storing extension information"""
    def __init__(self, db_name=DB_PATH):
        self.db_name = db_name
        self.create_tables()
    
    def create_tables(self):
        """Create the necessary tables if they don't exist"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Create extension_list table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS extension_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT,
            username TEXT UNIQUE,
            password TEXT,
            domain TEXT,
            status TEXT,
            registration_time TIMESTAMP
        )
        ''')
        
        conn.commit()
        conn.close()
        logging.info(f"Database initialized: {self.db_name}")
    
    def add_extension(self, display_name, username, password, domain, status="Not Registered"):
        """Add a new extension to the database"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            # Check if the extension already exists
            cursor.execute("SELECT id FROM extension_list WHERE username = ?", (username,))
            existing = cursor.fetchone()
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if existing:
                # Update existing extension
                cursor.execute('''
                UPDATE extension_list 
                SET display_name = ?, password = ?, domain = ?, status = ?, registration_time = ?
                WHERE username = ?
                ''', (display_name, password, domain, status, current_time, username))
                logging.info(f"Updated extension: {username}")
            else:
                # Insert new extension
                cursor.execute('''
                INSERT INTO extension_list (display_name, username, password, domain, status, registration_time)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (display_name, username, password, domain, status, current_time))
                logging.info(f"Added new extension: {username}")
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logging.info(f"Database error: {e}")
            return False
    
    def update_extension_status(self, username, status):
        """Update the registration status of an extension"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.execute('''
            UPDATE extension_list 
            SET status = ?, registration_time = ?
            WHERE username = ?
            ''', (status, current_time, username))
            
            conn.commit()
            conn.close()
            logging.info(f"Updated status for {username}: {status}")
            return True
        except Exception as e:
            logging.info(f"Database error: {e}")
            return False
    
    def delete_extension(self, username):
        """Delete an extension from the database"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM extension_list WHERE username = ?", (username,))
            
            conn.commit()
            conn.close()
            logging.info(f"Deleted extension: {username}")
            return True
        except Exception as e:
            logging.info(f"Database error: {e}")
            return False
    
    def get_all_extensions(self):
        """Get all extensions from the database"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT display_name, username, password, domain, status, registration_time FROM extension_list")
            extensions = cursor.fetchall()
            
            conn.close()
            return extensions
        except Exception as e:
            logging.info(f"Database error: {e}")
            return []
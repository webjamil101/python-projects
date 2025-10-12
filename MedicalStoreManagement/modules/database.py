import sqlite3
import os
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self, db_path='data/medical_store.db'):
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # Users table for authentication
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_login TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            # Medicines table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS medicines (
                    medicine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    generic_name TEXT,
                    batch_number TEXT UNIQUE NOT NULL,
                    manufacturer TEXT,
                    category TEXT,
                    price REAL NOT NULL,
                    cost_price REAL NOT NULL,
                    quantity INTEGER DEFAULT 0,
                    reorder_level INTEGER DEFAULT 10,
                    expiry_date TEXT NOT NULL,
                    description TEXT,
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            # Suppliers table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS suppliers (
                    supplier_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    contact_person TEXT,
                    phone TEXT,
                    email TEXT,
                    address TEXT,
                    tax_id TEXT,
                    payment_terms TEXT,
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            # Customers table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS customers (
                    customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    phone TEXT,
                    email TEXT,
                    address TEXT,
                    customer_type TEXT DEFAULT 'regular',
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            # Sales table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sales (
                    sale_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_id INTEGER,
                    total_amount REAL NOT NULL,
                    discount REAL DEFAULT 0,
                    tax_amount REAL DEFAULT 0,
                    final_amount REAL NOT NULL,
                    payment_method TEXT DEFAULT 'cash',
                    sale_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    created_by INTEGER,
                    FOREIGN KEY (customer_id) REFERENCES customers (customer_id),
                    FOREIGN KEY (created_by) REFERENCES users (user_id)
                )
            ''')
            
            # Sale items table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sale_items (
                    sale_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sale_id INTEGER,
                    medicine_id INTEGER,
                    quantity INTEGER NOT NULL,
                    unit_price REAL NOT NULL,
                    total_price REAL NOT NULL,
                    FOREIGN KEY (sale_id) REFERENCES sales (sale_id),
                    FOREIGN KEY (medicine_id) REFERENCES medicines (medicine_id)
                )
            ''')
            
            # Purchase orders table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS purchase_orders (
                    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    supplier_id INTEGER,
                    total_amount REAL NOT NULL,
                    order_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    expected_delivery TEXT,
                    status TEXT DEFAULT 'pending',
                    created_by INTEGER,
                    FOREIGN KEY (supplier_id) REFERENCES suppliers (supplier_id),
                    FOREIGN KEY (created_by) REFERENCES users (user_id)
                )
            ''')
            
            # Purchase order items table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS purchase_order_items (
                    order_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_id INTEGER,
                    medicine_id INTEGER,
                    quantity INTEGER NOT NULL,
                    unit_cost REAL NOT NULL,
                    total_cost REAL NOT NULL,
                    FOREIGN KEY (order_id) REFERENCES purchase_orders (order_id),
                    FOREIGN KEY (medicine_id) REFERENCES medicines (medicine_id)
                )
            ''')
            
            # Stock movements table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS stock_movements (
                    movement_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    medicine_id INTEGER,
                    movement_type TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    reference_id INTEGER,
                    movement_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT,
                    FOREIGN KEY (medicine_id) REFERENCES medicines (medicine_id)
                )
            ''')
    
    def execute_query(self, query, params=()):
        """Execute a query and return results"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            if query.strip().upper().startswith('SELECT'):
                return cursor.fetchall()
            return cursor.lastrowid
    
    def get_single_record(self, query, params=()):
        """Get a single record from database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()
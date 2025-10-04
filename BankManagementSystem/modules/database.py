import sqlite3
import os
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self, db_path=None):
        if db_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            data_dir = os.path.join(project_root, 'data')
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
            db_path = os.path.join(data_dir, 'bank.db')
        
        self.db_path = db_path
        print(f"Database path: {self.db_path}")
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
            # Customers table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS customers (
                    customer_id TEXT PRIMARY KEY,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT NOT NULL,
                    address TEXT,
                    date_of_birth TEXT,
                    id_type TEXT,
                    id_number TEXT,
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # Accounts table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    account_number TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL,
                    account_type TEXT NOT NULL,
                    balance REAL DEFAULT 0.0,
                    interest_rate REAL DEFAULT 0.0,
                    overdraft_limit REAL DEFAULT 0.0,
                    minimum_balance REAL DEFAULT 0.0,
                    opened_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (customer_id) REFERENCES customers (customer_id)
                )
            ''')
            
            # Transactions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY,
                    account_number TEXT NOT NULL,
                    transaction_type TEXT NOT NULL,
                    amount REAL NOT NULL,
                    description TEXT,
                    transaction_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    balance_after REAL,
                    status TEXT DEFAULT 'completed',
                    related_account TEXT,
                    FOREIGN KEY (account_number) REFERENCES accounts (account_number)
                )
            ''')
            
            # Loans table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS loans (
                    loan_id TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL,
                    loan_type TEXT NOT NULL,
                    principal_amount REAL NOT NULL,
                    interest_rate REAL NOT NULL,
                    term_months INTEGER NOT NULL,
                    monthly_payment REAL NOT NULL,
                    remaining_balance REAL NOT NULL,
                    issued_date TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (customer_id) REFERENCES customers (customer_id)
                )
            ''')
            
            # Employees table (for bank staff)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS employees (
                    employee_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    role TEXT DEFAULT 'teller',
                    permissions TEXT DEFAULT 'basic',
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            ''')
        print("✓ Database initialized successfully!")
    
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
import sqlite3
import json
import os
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self, db_path='library.db'):  # Simple filename in current directory
        self.db_path = db_path
        print(f"Using database: {self.db_path}")
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
            # Books table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS books (
                    book_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    author TEXT NOT NULL,
                    isbn TEXT UNIQUE,
                    genre TEXT,
                    publication_year INTEGER,
                    publisher TEXT,
                    total_copies INTEGER DEFAULT 1,
                    available_copies INTEGER DEFAULT 1,
                    location TEXT,
                    status TEXT DEFAULT 'available',
                    date_added TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Users table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT,
                    membership_type TEXT DEFAULT 'standard',
                    membership_status TEXT DEFAULT 'active',
                    max_books INTEGER DEFAULT 3,
                    total_borrowed INTEGER DEFAULT 0,
                    date_joined TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Transactions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    book_id TEXT NOT NULL,
                    borrow_date TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    return_date TEXT,
                    fine_amount REAL DEFAULT 0,
                    status TEXT DEFAULT 'borrowed',
                    FOREIGN KEY (user_id) REFERENCES users (user_id),
                    FOREIGN KEY (book_id) REFERENCES books (book_id)
                )
            ''')
            
            # Reservations table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS reservations (
                    reservation_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    book_id TEXT NOT NULL,
                    reservation_date TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    notification_sent INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (user_id),
                    FOREIGN KEY (book_id) REFERENCES books (book_id)
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
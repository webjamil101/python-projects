import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path='data/evm_database.db'):
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
            # Administrators table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS administrators (
                    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT DEFAULT 'election_officer',
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_login TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            # Voters table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS voters (
                    voter_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    voter_card_number TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    date_of_birth TEXT NOT NULL,
                    address TEXT NOT NULL,
                    constituency TEXT NOT NULL,
                    phone_number TEXT,
                    email TEXT,
                    is_verified INTEGER DEFAULT 0,
                    has_voted INTEGER DEFAULT 0,
                    registered_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    verification_code TEXT,
                    fingerprint_hash TEXT
                )
            ''')
            
            # Elections table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS elections (
                    election_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    election_name TEXT NOT NULL,
                    election_type TEXT NOT NULL,
                    constituency TEXT NOT NULL,
                    start_date TEXT NOT NULL,
                    end_date TEXT NOT NULL,
                    status TEXT DEFAULT 'scheduled',
                    description TEXT,
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    created_by INTEGER
                )
            ''')
            
            # Candidates table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    election_id INTEGER NOT NULL,
                    candidate_number INTEGER NOT NULL,
                    full_name TEXT NOT NULL,
                    party_name TEXT NOT NULL,
                    party_symbol TEXT,
                    constituency TEXT NOT NULL,
                    photo_url TEXT,
                    manifesto TEXT,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (election_id) REFERENCES elections (election_id)
                )
            ''')
            
            # Votes table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS votes (
                    vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    election_id INTEGER NOT NULL,
                    voter_id INTEGER NOT NULL,
                    candidate_id INTEGER NOT NULL,
                    vote_timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    voting_machine_id TEXT,
                    vote_hash TEXT UNIQUE NOT NULL,
                    is_verified INTEGER DEFAULT 1,
                    FOREIGN KEY (election_id) REFERENCES elections (election_id),
                    FOREIGN KEY (voter_id) REFERENCES voters (voter_id),
                    FOREIGN KEY (candidate_id) REFERENCES candidates (candidate_id),
                    UNIQUE(election_id, voter_id)
                )
            ''')
            
            # Audit log table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_type TEXT NOT NULL,
                    user_type TEXT NOT NULL,
                    user_id INTEGER,
                    description TEXT NOT NULL,
                    ip_address TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    additional_data TEXT
                )
            ''')
            
            # Voting sessions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS voting_sessions (
                    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    election_id INTEGER NOT NULL,
                    machine_id TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT DEFAULT 'active',
                    total_votes INTEGER DEFAULT 0,
                    created_by INTEGER,
                    FOREIGN KEY (election_id) REFERENCES elections (election_id)
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
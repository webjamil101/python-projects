"""
Database configuration and connection management
"""

import sqlite3
import hashlib
from datetime import datetime
from typing import Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Handles all database operations and connection management"""
    
    def __init__(self, db_name: str = "academic_management.db"):
        self.db_name = db_name
        self.init_database()
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        return sqlite3.connect(self.db_name)
    
    def init_database(self):
        """Initialize database with required tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('admin', 'faculty', 'student')),
                        email TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE
                    )
                ''')
                
                # Students table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS students (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER UNIQUE,
                        student_id TEXT UNIQUE NOT NULL,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        date_of_birth DATE,
                        gender TEXT CHECK(gender IN ('Male', 'Female', 'Other')),
                        phone TEXT,
                        address TEXT,
                        enrollment_date DATE DEFAULT CURRENT_DATE,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Faculty table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS faculty (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER UNIQUE,
                        faculty_id TEXT UNIQUE NOT NULL,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        department TEXT NOT NULL,
                        designation TEXT,
                        phone TEXT,
                        email TEXT,
                        hire_date DATE DEFAULT CURRENT_DATE,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Courses table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS courses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        course_code TEXT UNIQUE NOT NULL,
                        course_name TEXT NOT NULL,
                        description TEXT,
                        credits INTEGER NOT NULL,
                        department TEXT,
                        semester INTEGER,
                        faculty_id INTEGER,
                        max_students INTEGER DEFAULT 30,
                        is_active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (faculty_id) REFERENCES faculty (id)
                    )
                ''')
                
                # Enrollments table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS enrollments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        student_id INTEGER,
                        course_id INTEGER,
                        enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'Enrolled' CHECK(status IN ('Enrolled', 'Completed', 'Dropped')),
                        UNIQUE(student_id, course_id),
                        FOREIGN KEY (student_id) REFERENCES students (id),
                        FOREIGN KEY (course_id) REFERENCES courses (id)
                    )
                ''')
                
                # Grades table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS grades (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        enrollment_id INTEGER,
                        assignment_score REAL DEFAULT 0,
                        midterm_score REAL DEFAULT 0,
                        final_score REAL DEFAULT 0,
                        project_score REAL DEFAULT 0,
                        total_score REAL GENERATED ALWAYS AS (
                            assignment_score * 0.2 + 
                            midterm_score * 0.3 + 
                            final_score * 0.4 + 
                            project_score * 0.1
                        ) VIRTUAL,
                        grade TEXT GENERATED ALWAYS AS (
                            CASE 
                                WHEN total_score >= 90 THEN 'A'
                                WHEN total_score >= 80 THEN 'B'
                                WHEN total_score >= 70 THEN 'C'
                                WHEN total_score >= 60 THEN 'D'
                                ELSE 'F'
                            END
                        ) VIRTUAL,
                        graded_by INTEGER,
                        graded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (enrollment_id) REFERENCES enrollments (id),
                        FOREIGN KEY (graded_by) REFERENCES faculty (id)
                    )
                ''')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    def execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a query and return cursor"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor
    
    def fetch_all(self, query: str, params: tuple = ()) -> list:
        """Fetch all results from query"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def fetch_one(self, query: str, params: tuple = ()) -> Optional[tuple]:
        """Fetch single result from query"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()
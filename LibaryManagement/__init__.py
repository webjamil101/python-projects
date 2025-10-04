"""
Library Management System
A comprehensive library management system with book tracking, user management,
and transaction processing.

Author: Your Name
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from modules.book import Book, BookManager
from modules.user import User, UserManager
from modules.transaction import Transaction, TransactionManager
from modules.database import DatabaseManager
from modules.utils import Utilities, ValidationError

__all__ = [
    # Classes
    'Book',
    'BookManager', 
    'User',
    'UserManager',
    'Transaction',
    'TransactionManager',
    'DatabaseManager',
    'Utilities',
    'ValidationError',
    
    # Modules
    'book',
    'user', 
    'transaction',
    'database',
    'utils'
]

# Package initialization
def initialize_database(db_path='data/library.db'):
    """Initialize the database with required tables"""
    from modules.database import DatabaseManager
    db = DatabaseManager(db_path)
    print("Database initialized successfully!")
    return db

def get_version():
    """Return the current version of the package"""
    return __version__

# Create package-level instances for easy access
book_manager = BookManager()
user_manager = UserManager()
transaction_manager = TransactionManager()

print(f"Library Management System {__version__} initialized successfully!")
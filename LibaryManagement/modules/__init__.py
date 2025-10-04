"""
Library Management System Modules
This package contains all the core modules for the library management system.

Modules:
- book: Book and BookManager classes for book operations
- user: User and UserManager classes for user operations  
- transaction: Transaction and TransactionManager classes for borrowing/returning
- database: DatabaseManager class for database operations
- utils: Utility functions and helper classes
"""

__all__ = [
    'book',
    'user', 
    'transaction',
    'database',
    'utils'
]

# Import key classes for easy access
from .book import Book, BookManager
from .user import User, UserManager
from .transaction import Transaction, TransactionManager
from .database import DatabaseManager
from .utils import Utilities, ValidationError

# Module version
__version__ = "1.0.0"

def get_module_info():
    """Return information about available modules"""
    return {
        'book': 'Handles book-related operations and management',
        'user': 'Manages user registration and membership',
        'transaction': 'Processes book borrowing and returning',
        'database': 'Database connection and management',
        'utils': 'Utility functions and helper methods'
    }

# Initialize database connection when module is imported
def init():
    """Initialize the modules package"""
    from .database import DatabaseManager
    db = DatabaseManager()
    return db

# Auto-initialize when package is imported
try:
    init()
    print("Library modules initialized successfully!")
except Exception as e:
    print(f"Warning: Could not initialize database: {e}")
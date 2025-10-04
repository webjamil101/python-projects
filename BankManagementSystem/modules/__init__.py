"""
Bank Management System Modules
A comprehensive banking system with account management, transactions, and reporting.
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .account import Account, AccountManager
from .customer import Customer, CustomerManager
from .transaction import Transaction, TransactionManager
from .database import DatabaseManager
from .utils import Utilities, ValidationError, Security
from .reports import ReportGenerator

__all__ = [
    'Account',
    'AccountManager',
    'Customer', 
    'CustomerManager',
    'Transaction',
    'TransactionManager',
    'DatabaseManager',
    'Utilities',
    'ValidationError',
    'Security',
    'ReportGenerator'
]

def initialize_system():
    """Initialize the banking system"""
    try:
        from .database import DatabaseManager
        db = DatabaseManager()
        print("Bank Management System initialized successfully!")
        return db
    except Exception as e:
        print(f"Warning: System initialization failed: {e}")
        return None

# Auto-initialize
system_db = initialize_system()
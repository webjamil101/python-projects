"""
Medical Store Management System
A comprehensive system for managing pharmacy operations with secure authentication.
"""

__version__ = "1.0.0"
__author__ = "Medical Store Management"

from .auth import Authentication
from .medicine import MedicineManager
from .supplier import SupplierManager
from .customer import CustomerManager
from .sales import SalesManager
from .inventory import InventoryManager
from .reports import ReportGenerator
from .database import DatabaseManager

__all__ = [
    'Authentication',
    'MedicineManager',
    'SupplierManager',
    'CustomerManager',
    'SalesManager',
    'InventoryManager',
    'ReportGenerator',
    'DatabaseManager'
]
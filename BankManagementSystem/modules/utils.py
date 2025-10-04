import json
from datetime import datetime, timedelta
from uuid import uuid4
import re
import hashlib
import secrets

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class Security:
    @staticmethod
    def hash_password(password):
        """Hash a password for storing"""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return f"{salt}${pwd_hash.hex()}"
    
    @staticmethod
    def verify_password(stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt, stored_hash = stored_password.split('$')
        pwd_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return pwd_hash.hex() == stored_hash

class Utilities:
    @staticmethod
    def generate_id():
        """Generate unique ID"""
        return str(uuid4())[:8]
    
    @staticmethod
    def generate_account_number():
        """Generate bank account number"""
        return f"ACC{str(uuid4())[:8].upper()}"
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            raise ValidationError("Invalid email format")
        return True
    
    @staticmethod
    def validate_phone(phone):
        """Validate phone number"""
        pattern = r'^\+?1?\d{9,15}$'
        if not re.match(pattern, phone):
            raise ValidationError("Invalid phone number")
        return True
    
    @staticmethod
    def validate_amount(amount):
        """Validate monetary amount"""
        try:
            amount_float = float(amount)
            if amount_float <= 0:
                raise ValidationError("Amount must be positive")
            return amount_float
        except ValueError:
            raise ValidationError("Invalid amount format")
    
    @staticmethod
    def format_currency(amount):
        """Format amount as currency"""
        return f"${amount:,.2f}"
    
    @staticmethod
    def get_current_date():
        """Get current date"""
        return datetime.now().date()
    
    @staticmethod
    def format_date(date_string):
        """Format date string to datetime object"""
        return datetime.strptime(date_string, '%Y-%m-%d')
    
    @staticmethod
    def calculate_future_date(months=0, days=0):
        """Calculate future date"""
        return datetime.now() + timedelta(days=days) + timedelta(days=months*30)
    
    @staticmethod
    def validate_age(date_of_birth):
        """Validate customer is at least 18 years old"""
        dob = Utilities.format_date(date_of_birth)
        age = (datetime.now() - dob).days // 365
        if age < 18:
            raise ValidationError("Customer must be at least 18 years old")
        return True
import json
from datetime import datetime, timedelta
from uuid import uuid4
import re

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class Utilities:
    @staticmethod
    def generate_id():
        """Generate unique ID"""
        return str(uuid4())[:8]
    
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
    def calculate_fine(return_date, due_date):
        """Calculate fine for late return"""
        if return_date > due_date:
            days_late = (return_date - due_date).days
            return days_late * 5  # $5 per day
        return 0
    
    @staticmethod
    def format_date(date_string):
        """Format date string to datetime object"""
        return datetime.strptime(date_string, '%Y-%m-%d')
    
    @staticmethod
    def get_current_date():
        """Get current date"""
        return datetime.now().date()
    
    @staticmethod
    def get_due_date(period_days=14):
        """Calculate due date"""
        return datetime.now() + timedelta(days=period_days)
"""
Utility functions and helpers
"""

import re
from datetime import datetime
from typing import Optional, Tuple  # Added Tuple import

class Validators:
    """Input validation utilities"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Validate phone number format"""
        pattern = r'^\+?1?\d{9,15}$'
        return bool(re.match(pattern, phone))
    
    @staticmethod
    def validate_date(date_string: str, format: str = '%Y-%m-%d') -> bool:
        """Validate date format"""
        try:
            datetime.strptime(date_string, format)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(char.isdigit() for char in password):
            return False, "Password must contain at least one digit"
        if not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter"
        return True, "Password is strong"

class Formatters:
    """Data formatting utilities"""
    
    @staticmethod
    def format_date(date_string: str, input_format: str = '%Y-%m-%d', output_format: str = '%B %d, %Y') -> str:
        """Format date string"""
        try:
            date_obj = datetime.strptime(date_string, input_format)
            return date_obj.strftime(output_format)
        except ValueError:
            return date_string
    
    @staticmethod
    def format_name(first_name: str, last_name: str) -> str:
        """Format full name"""
        return f"{first_name} {last_name}".title()
    
    @staticmethod
    def format_gpa(gpa: float) -> str:
        """Format GPA with 2 decimal places"""
        return f"{gpa:.2f}"

class ReportGenerator:
    """Report generation utilities"""
    
    @staticmethod
    def generate_student_report(student_data: dict, grades: list) -> str:
        """Generate student report"""
        report = f"STUDENT REPORT\n"
        report += f"==============\n"
        report += f"Student ID: {student_data.get('student_id', 'N/A')}\n"
        report += f"Name: {student_data.get('first_name', '')} {student_data.get('last_name', '')}\n"
        report += f"Enrollment Date: {student_data.get('enrollment_date', 'N/A')}\n\n"
        report += f"COURSES AND GRADES:\n"
        report += f"-------------------\n"
        
        for grade in grades:
            report += f"{grade['course_code']}: {grade.get('grade', 'N/A')} "
            report += f"({grade.get('total_score', 0):.1f}%)\n"
        
        return report
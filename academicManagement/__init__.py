"""
Academic Management System
A comprehensive system for managing students, courses, grades, and faculty.
"""

__version__ = "1.0.0"
__author__ = "Academic Management System Team"
__description__ = "Advanced Academic Management System using Python"

# Import key classes for easier access
from .database import DatabaseManager
from .auth import Authentication
from .student_management import StudentManager
from .course_management import CourseManager
from .grade_management import GradeManager
from .faculty_management import FacultyManager

# Define what should be imported with "from academic_management import *"
__all__ = [
    'DatabaseManager',
    'Authentication', 
    'StudentManager',
    'CourseManager',
    'GradeManager',
    'FacultyManager',
    'models'
]
"""
Data models for the academic management system
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class User:
    id: Optional[int]
    username: str
    password_hash: str
    role: str
    email: str
    created_at: Optional[datetime] = None
    is_active: bool = True

@dataclass
class Student:
    id: Optional[int]
    user_id: Optional[int]
    student_id: str
    first_name: str
    last_name: str
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    enrollment_date: Optional[str] = None

@dataclass
class Faculty:
    id: Optional[int]
    user_id: Optional[int]
    faculty_id: str
    first_name: str
    last_name: str
    department: str
    designation: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    hire_date: Optional[str] = None

@dataclass
class Course:
    id: Optional[int]
    course_code: str
    course_name: str
    description: Optional[str] = None
    credits: int = 3
    department: Optional[str] = None
    semester: Optional[int] = None
    faculty_id: Optional[int] = None
    max_students: int = 30
    is_active: bool = True
    created_at: Optional[datetime] = None

@dataclass
class Enrollment:
    id: Optional[int]
    student_id: int
    course_id: int
    enrollment_date: Optional[datetime] = None
    status: str = "Enrolled"

@dataclass
class Grade:
    id: Optional[int]
    enrollment_id: int
    assignment_score: float = 0.0
    midterm_score: float = 0.0
    final_score: float = 0.0
    project_score: float = 0.0
    total_score: Optional[float] = None
    grade: Optional[str] = None
    graded_by: Optional[int] = None
    graded_at: Optional[datetime] = None
"""
Student management module
"""

from typing import List, Optional, Tuple  # Added Tuple import
from database import DatabaseManager
from models import Student

class StudentManager:
    """Manages student-related operations"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def add_student(self, student: Student) -> Tuple[bool, str]:
        """Add a new student"""
        try:
            self.db.execute_query('''
                INSERT INTO students (user_id, student_id, first_name, last_name, 
                                    date_of_birth, gender, phone, address, enrollment_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                student.user_id, student.student_id, student.first_name, student.last_name,
                student.date_of_birth, student.gender, student.phone, student.address,
                student.enrollment_date
            ))
            return True, "Student added successfully"
        except Exception as e:
            return False, f"Failed to add student: {str(e)}"
    
    def get_student(self, student_id: str) -> Optional[Student]:
        """Get student by student ID"""
        result = self.db.fetch_one(
            "SELECT * FROM students WHERE student_id = ?", (student_id,)
        )
        if result:
            return Student(*result)
        return None
    
    def get_all_students(self) -> List[Student]:
        """Get all students"""
        results = self.db.fetch_all(
            "SELECT * FROM students ORDER BY last_name, first_name"
        )
        return [Student(*row) for row in results]
    
    def update_student(self, student_id: str, **kwargs) -> Tuple[bool, str]:
        """Update student information"""
        try:
            if not kwargs:
                return False, "No fields to update"
            
            set_clause = ", ".join([f"{key} = ?" for key in kwargs.keys()])
            values = list(kwargs.values())
            values.append(student_id)
            
            self.db.execute_query(
                f"UPDATE students SET {set_clause} WHERE student_id = ?",
                tuple(values)
            )
            return True, "Student updated successfully"
        except Exception as e:
            return False, f"Failed to update student: {str(e)}"
    
    def delete_student(self, student_id: str) -> Tuple[bool, str]:
        """Delete a student"""
        try:
            self.db.execute_query(
                "DELETE FROM students WHERE student_id = ?", (student_id,)
            )
            return True, "Student deleted successfully"
        except Exception as e:
            return False, f"Failed to delete student: {str(e)}"
    
    def search_students(self, search_term: str) -> List[Student]:
        """Search students by name or student ID"""
        results = self.db.fetch_all('''
            SELECT * FROM students 
            WHERE first_name LIKE ? OR last_name LIKE ? OR student_id LIKE ?
            ORDER BY last_name, first_name
        ''', (f"%{search_term}%", f"%{search_term}%", f"%{search_term}%"))
        
        return [Student(*row) for row in results]
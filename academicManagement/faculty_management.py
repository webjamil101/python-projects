"""
Faculty management module
"""

from typing import List, Optional, Tuple  # Added Tuple import
from database import DatabaseManager
from models import Faculty

class FacultyManager:
    """Manages faculty-related operations"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def add_faculty(self, faculty: Faculty) -> Tuple[bool, str]:
        """Add a new faculty member"""
        try:
            self.db.execute_query('''
                INSERT INTO faculty (user_id, faculty_id, first_name, last_name, 
                                   department, designation, phone, email, hire_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                faculty.user_id, faculty.faculty_id, faculty.first_name, faculty.last_name,
                faculty.department, faculty.designation, faculty.phone, faculty.email,
                faculty.hire_date
            ))
            return True, "Faculty added successfully"
        except Exception as e:
            return False, f"Failed to add faculty: {str(e)}"
    
    def get_faculty(self, faculty_id: str) -> Optional[Faculty]:
        """Get faculty by faculty ID"""
        result = self.db.fetch_one(
            "SELECT * FROM faculty WHERE faculty_id = ?", (faculty_id,)
        )
        if result:
            return Faculty(*result)
        return None
    
    def get_all_faculty(self) -> List[Faculty]:
        """Get all faculty members"""
        results = self.db.fetch_all(
            "SELECT * FROM faculty ORDER BY last_name, first_name"
        )
        return [Faculty(*row) for row in results]
    
    def update_faculty(self, faculty_id: str, **kwargs) -> Tuple[bool, str]:
        """Update faculty information"""
        try:
            if not kwargs:
                return False, "No fields to update"
            
            set_clause = ", ".join([f"{key} = ?" for key in kwargs.keys()])
            values = list(kwargs.values())
            values.append(faculty_id)
            
            self.db.execute_query(
                f"UPDATE faculty SET {set_clause} WHERE faculty_id = ?",
                tuple(values)
            )
            return True, "Faculty updated successfully"
        except Exception as e:
            return False, f"Failed to update faculty: {str(e)}"
    
    def delete_faculty(self, faculty_id: str) -> Tuple[bool, str]:
        """Delete a faculty member"""
        try:
            self.db.execute_query(
                "DELETE FROM faculty WHERE faculty_id = ?", (faculty_id,)
            )
            return True, "Faculty deleted successfully"
        except Exception as e:
            return False, f"Failed to delete faculty: {str(e)}"
    
    def get_faculty_by_department(self, department: str) -> List[Faculty]:
        """Get faculty by department"""
        results = self.db.fetch_all(
            "SELECT * FROM faculty WHERE department = ? ORDER BY last_name, first_name",
            (department,)
        )
        return [Faculty(*row) for row in results]
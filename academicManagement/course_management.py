"""
Course management module
"""

from typing import List, Optional, Tuple  # Added Tuple import
from database import DatabaseManager
from models import Course

class CourseManager:
    """Manages course-related operations"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def add_course(self, course: Course) -> Tuple[bool, str]:
        """Add a new course"""
        try:
            self.db.execute_query('''
                INSERT INTO courses (course_code, course_name, description, credits, 
                                   department, semester, faculty_id, max_students)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                course.course_code, course.course_name, course.description, course.credits,
                course.department, course.semester, course.faculty_id, course.max_students
            ))
            return True, "Course added successfully"
        except Exception as e:
            return False, f"Failed to add course: {str(e)}"
    
    def get_course(self, course_code: str) -> Optional[Course]:
        """Get course by course code"""
        result = self.db.fetch_one(
            "SELECT * FROM courses WHERE course_code = ? AND is_active = TRUE", 
            (course_code,)
        )
        if result:
            return Course(*result)
        return None
    
    def get_all_courses(self) -> List[Course]:
        """Get all active courses"""
        results = self.db.fetch_all(
            "SELECT * FROM courses WHERE is_active = TRUE ORDER BY course_code"
        )
        return [Course(*row) for row in results]
    
    def update_course(self, course_code: str, **kwargs) -> Tuple[bool, str]:
        """Update course information"""
        try:
            if not kwargs:
                return False, "No fields to update"
            
            set_clause = ", ".join([f"{key} = ?" for key in kwargs.keys()])
            values = list(kwargs.values())
            values.append(course_code)
            
            self.db.execute_query(
                f"UPDATE courses SET {set_clause} WHERE course_code = ?",
                tuple(values)
            )
            return True, "Course updated successfully"
        except Exception as e:
            return False, f"Failed to update course: {str(e)}"
    
    def delete_course(self, course_code: str) -> Tuple[bool, str]:
        """Soft delete a course"""
        try:
            self.db.execute_query(
                "UPDATE courses SET is_active = FALSE WHERE course_code = ?", 
                (course_code,)
            )
            return True, "Course deleted successfully"
        except Exception as e:
            return False, f"Failed to delete course: {str(e)}"
    
    def get_courses_by_department(self, department: str) -> List[Course]:
        """Get courses by department"""
        results = self.db.fetch_all(
            "SELECT * FROM courses WHERE department = ? AND is_active = TRUE ORDER BY course_code",
            (department,)
        )
        return [Course(*row) for row in results]
    
    def get_courses_by_faculty(self, faculty_id: int) -> List[Course]:
        """Get courses taught by a faculty member"""
        results = self.db.fetch_all(
            "SELECT * FROM courses WHERE faculty_id = ? AND is_active = TRUE ORDER BY course_code",
            (faculty_id,)
        )
        return [Course(*row) for row in results]
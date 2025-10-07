"""
Grade management module
"""

from typing import List, Optional, Tuple, Dict  # Added Tuple import
from database import DatabaseManager
from models import Grade, Enrollment

class GradeManager:
    """Manages grade-related operations"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def enroll_student(self, student_id: int, course_id: int) -> Tuple[bool, str]:
        """Enroll student in a course"""
        try:
            # Check if already enrolled
            existing = self.db.fetch_one(
                "SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?",
                (student_id, course_id)
            )
            if existing:
                return False, "Student already enrolled in this course"
            
            self.db.execute_query(
                "INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)",
                (student_id, course_id)
            )
            return True, "Student enrolled successfully"
        except Exception as e:
            return False, f"Failed to enroll student: {str(e)}"
    
    def add_grade(self, grade: Grade) -> Tuple[bool, str]:
        """Add or update grades for a student"""
        try:
            # Check if grade record exists
            existing = self.db.fetch_one(
                "SELECT id FROM grades WHERE enrollment_id = ?", (grade.enrollment_id,)
            )
            
            if existing:
                # Update existing grade
                self.db.execute_query('''
                    UPDATE grades SET 
                    assignment_score = ?, midterm_score = ?, final_score = ?, project_score = ?,
                    graded_by = ?, graded_at = CURRENT_TIMESTAMP
                    WHERE enrollment_id = ?
                ''', (
                    grade.assignment_score, grade.midterm_score, grade.final_score,
                    grade.project_score, grade.graded_by, grade.enrollment_id
                ))
                return True, "Grade updated successfully"
            else:
                # Insert new grade
                self.db.execute_query('''
                    INSERT INTO grades (enrollment_id, assignment_score, midterm_score, 
                                      final_score, project_score, graded_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    grade.enrollment_id, grade.assignment_score, grade.midterm_score,
                    grade.final_score, grade.project_score, grade.graded_by
                ))
                return True, "Grade added successfully"
        except Exception as e:
            return False, f"Failed to add grade: {str(e)}"
    
    def get_student_grades(self, student_id: int) -> List[Dict]:
        """Get all grades for a student"""
        results = self.db.fetch_all('''
            SELECT 
                c.course_code, c.course_name, c.credits,
                g.assignment_score, g.midterm_score, g.final_score, g.project_score,
                g.total_score, g.grade
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN grades g ON e.id = g.enrollment_id
            WHERE e.student_id = ? AND e.status = 'Enrolled'
            ORDER BY c.course_code
        ''', (student_id,))
        
        return [
            {
                'course_code': row[0], 'course_name': row[1], 'credits': row[2],
                'assignment_score': row[3], 'midterm_score': row[4], 'final_score': row[5],
                'project_score': row[6], 'total_score': row[7], 'grade': row[8]
            }
            for row in results
        ]
    
    def get_course_grades(self, course_id: int) -> List[Dict]:
        """Get all grades for a course"""
        results = self.db.fetch_all('''
            SELECT 
                s.student_id, s.first_name, s.last_name,
                g.assignment_score, g.midterm_score, g.final_score, g.project_score,
                g.total_score, g.grade
            FROM enrollments e
            JOIN students s ON e.student_id = s.id
            LEFT JOIN grades g ON e.id = g.enrollment_id
            WHERE e.course_id = ? AND e.status = 'Enrolled'
            ORDER BY s.last_name, s.first_name
        ''', (course_id,))
        
        return [
            {
                'student_id': row[0], 'first_name': row[1], 'last_name': row[2],
                'assignment_score': row[3], 'midterm_score': row[4], 'final_score': row[5],
                'project_score': row[6], 'total_score': row[7], 'grade': row[8]
            }
            for row in results
        ]
    
    def calculate_gpa(self, student_id: int) -> float:
        """Calculate GPA for a student"""
        results = self.db.fetch_all('''
            SELECT c.credits, g.grade
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN grades g ON e.id = g.enrollment_id
            WHERE e.student_id = ? AND e.status = 'Enrolled' AND g.grade IS NOT NULL
        ''', (student_id,))
        
        if not results:
            return 0.0
        
        grade_points = {'A': 4.0, 'B': 3.0, 'C': 2.0, 'D': 1.0, 'F': 0.0}
        total_credits = 0
        total_points = 0
        
        for credits, grade in results:
            if grade in grade_points:
                total_credits += credits
                total_points += credits * grade_points[grade]
        
        return round(total_points / total_credits, 2) if total_credits > 0 else 0.0
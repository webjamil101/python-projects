"""
Main application file for Academic Management System
"""

import sys
from database import DatabaseManager
from auth import Authentication
from student_management import StudentManager
from course_management import CourseManager
from grade_management import GradeManager
from faculty_management import FacultyManager
from models import User, Student, Course, Faculty
from utils import Validators

class AcademicManagementSystem:
    """Main application class"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.auth = Authentication(self.db)
        self.student_manager = StudentManager(self.db)
        self.course_manager = CourseManager(self.db)
        self.grade_manager = GradeManager(self.db)
        self.faculty_manager = FacultyManager(self.db)
        self.current_user = None
    
    def display_menu(self):
        """Display main menu based on user role"""
        if not self.current_user:
            self.show_login_menu()
        else:
            if self.current_user.role == 'admin':
                self.show_admin_menu()
            elif self.current_user.role == 'faculty':
                self.show_faculty_menu()
            elif self.current_user.role == 'student':
                self.show_student_menu()
    
    def show_login_menu(self):
        """Display login menu"""
        print("\n" + "="*50)
        print("ACADEMIC MANAGEMENT SYSTEM")
        print("="*50)
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        print("="*50)
        
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == '1':
            self.login()
        elif choice == '2':
            self.register()
        elif choice == '3':
            print("Thank you for using Academic Management System!")
            sys.exit()
        else:
            print("Invalid choice. Please try again.")
    
    def show_admin_menu(self):
        """Display admin menu"""
        print("\n" + "="*50)
        print(f"ADMIN DASHBOARD - Welcome, {self.current_user.username}!")
        print("="*50)
        print("1. Manage Students")
        print("2. Manage Faculty")
        print("3. Manage Courses")
        print("4. View Reports")
        print("5. Logout")
        print("="*50)
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == '1':
            self.manage_students()
        elif choice == '2':
            self.manage_faculty()
        elif choice == '3':
            self.manage_courses()
        elif choice == '4':
            self.view_reports()
        elif choice == '5':
            self.logout()
        else:
            print("Invalid choice. Please try again.")
    
    def show_faculty_menu(self):
        """Display faculty menu"""
        print("\n" + "="*50)
        print(f"FACULTY DASHBOARD - Welcome, {self.current_user.username}!")
        print("="*50)
        print("1. View My Courses")
        print("2. Manage Grades")
        print("3. View Students")
        print("4. Logout")
        print("="*50)
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            self.view_faculty_courses()
        elif choice == '2':
            self.manage_grades()
        elif choice == '3':
            self.view_students()
        elif choice == '4':
            self.logout()
        else:
            print("Invalid choice. Please try again.")
    
    def show_student_menu(self):
        """Display student menu"""
        print("\n" + "="*50)
        print(f"STUDENT DASHBOARD - Welcome, {self.current_user.username}!")
        print("="*50)
        print("1. View My Courses")
        print("2. View My Grades")
        print("3. View GPA")
        print("4. Logout")
        print("="*50)
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            self.view_student_courses()
        elif choice == '2':
            self.view_student_grades()
        elif choice == '3':
            self.view_student_gpa()
        elif choice == '4':
            self.logout()
        else:
            print("Invalid choice. Please try again.")
    
    def login(self):
        """Handle user login"""
        print("\n--- Login ---")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        success, message, user = self.auth.login(username, password)
        print(message)
        
        if success:
            self.current_user = user
    
    def register(self):
        """Handle user registration"""
        print("\n--- Register ---")
        username = input("Username: ").strip()
        email = input("Email: ").strip()
        password = input("Password: ").strip()
        confirm_password = input("Confirm Password: ").strip()
        role = input("Role (student/faculty): ").strip().lower()
        
        if role not in ['student', 'faculty']:
            print("Invalid role. Only 'student' or 'faculty' allowed.")
            return
        
        if password != confirm_password:
            print("Passwords do not match.")
            return
        
        # Validate password strength
        is_valid, msg = Validators.validate_password(password)
        if not is_valid:
            print(f"Password validation failed: {msg}")
            return
        
        if not Validators.validate_email(email):
            print("Invalid email format.")
            return
        
        success, message = self.auth.register_user(username, password, email, role)
        print(message)
    
    def logout(self):
        """Handle user logout"""
        success, message = self.auth.logout()
        print(message)
        self.current_user = None
    
    def manage_students(self):
        """Admin: Manage students"""
        print("\n--- Manage Students ---")
        print("1. Add Student")
        print("2. View All Students")
        print("3. Search Student")
        print("4. Update Student")
        print("5. Delete Student")
        print("6. Back to Main Menu")
        
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == '1':
            self.add_student()
        elif choice == '2':
            self.view_all_students()
        elif choice == '3':
            self.search_student()
        elif choice == '4':
            self.update_student()
        elif choice == '5':
            self.delete_student()
        elif choice == '6':
            return
        else:
            print("Invalid choice.")
    
    def add_student(self):
        """Add a new student"""
        print("\n--- Add New Student ---")
        student_id = input("Student ID: ").strip()
        first_name = input("First Name: ").strip()
        last_name = input("Last Name: ").strip()
        date_of_birth = input("Date of Birth (YYYY-MM-DD): ").strip()
        gender = input("Gender (Male/Female/Other): ").strip()
        phone = input("Phone: ").strip()
        address = input("Address: ").strip()
        
        student = Student(
            id=None,
            user_id=None,
            student_id=student_id,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            gender=gender,
            phone=phone,
            address=address
        )
        
        success, message = self.student_manager.add_student(student)
        print(message)
    
    def view_all_students(self):
        """View all students"""
        print("\n--- All Students ---")
        students = self.student_manager.get_all_students()
        
        if not students:
            print("No students found.")
            return
        
        for student in students:
            print(f"ID: {student.student_id}, Name: {student.first_name} {student.last_name}, "
                  f"Phone: {student.phone}, Enrollment: {student.enrollment_date}")
    
    # Additional methods for other functionalities would be implemented similarly
    
    def run(self):
        """Main application loop"""
        print("Welcome to Academic Management System!")
        
        while True:
            try:
                self.display_menu()
            except KeyboardInterrupt:
                print("\n\nThank you for using Academic Management System!")
                break
            except Exception as e:
                print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Create default admin user
    db = DatabaseManager()
    auth = Authentication(db)
    
    # Check if admin user exists, if not create one
    admin_exists = db.fetch_one("SELECT id FROM users WHERE username = 'admin'")
    if not admin_exists:
        auth.register_user('admin', 'admin123', 'admin@university.edu', 'admin')
        print("Default admin user created: username='admin', password='admin123'")
    
    # Run the application
    app = AcademicManagementSystem()
    app.run()
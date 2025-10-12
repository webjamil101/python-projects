import bcrypt
import sqlite3
from datetime import datetime
from .database import DatabaseManager

class Authentication:
    def __init__(self):
        self.db = DatabaseManager()
        self.current_user = None
        self.create_default_admin()
    
    def create_default_admin(self):
        """Create default admin user if not exists"""
        try:
            # Check if admin user exists
            result = self.db.get_single_record(
                "SELECT * FROM users WHERE username = ?", 
                ('admin',)
            )
            
            if not result:
                # Create default admin user
                password_hash = self.hash_password('admin123')
                self.db.execute_query('''
                    INSERT INTO users (username, password_hash, full_name, role)
                    VALUES (?, ?, ?, ?)
                ''', ('admin', password_hash, 'System Administrator', 'admin'))
                print("Default admin user created: admin/admin123")
        except Exception as e:
            print(f"Warning: Could not create default admin: {e}")
    
    def hash_password(self, password):
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt)
    
    def verify_password(self, password, hashed_password):
        """Verify a password against its hash"""
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    
    def login(self, username, password):
        """Authenticate user"""
        try:
            user = self.db.get_single_record(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (username,)
            )
            
            if user and self.verify_password(password, user['password_hash']):
                # Update last login
                self.db.execute_query(
                    "UPDATE users SET last_login = ? WHERE user_id = ?",
                    (datetime.now().isoformat(), user['user_id'])
                )
                
                self.current_user = {
                    'user_id': user['user_id'],
                    'username': user['username'],
                    'full_name': user['full_name'],
                    'role': user['role']
                }
                return True, "Login successful!"
            else:
                return False, "Invalid username or password"
                
        except Exception as e:
            return False, f"Login error: {e}"
    
    def logout(self):
        """Logout current user"""
        self.current_user = None
        return True, "Logged out successfully"
    
    def create_user(self, username, password, full_name, role):
        """Create a new user (admin only)"""
        if not self.current_user or self.current_user['role'] != 'admin':
            return False, "Permission denied. Admin access required."
        
        try:
            # Check if username exists
            existing_user = self.db.get_single_record(
                "SELECT * FROM users WHERE username = ?", 
                (username,)
            )
            
            if existing_user:
                return False, "Username already exists"
            
            # Create new user
            password_hash = self.hash_password(password)
            self.db.execute_query('''
                INSERT INTO users (username, password_hash, full_name, role)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, full_name, role))
            
            return True, f"User {username} created successfully"
            
        except Exception as e:
            return False, f"Error creating user: {e}"
    
    def change_password(self, old_password, new_password):
        """Change current user's password"""
        if not self.current_user:
            return False, "No user logged in"
        
        try:
            # Verify old password
            user = self.db.get_single_record(
                "SELECT password_hash FROM users WHERE user_id = ?",
                (self.current_user['user_id'],)
            )
            
            if not self.verify_password(old_password, user['password_hash']):
                return False, "Current password is incorrect"
            
            # Update password
            new_password_hash = self.hash_password(new_password)
            self.db.execute_query(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (new_password_hash, self.current_user['user_id'])
            )
            
            return True, "Password changed successfully"
            
        except Exception as e:
            return False, f"Error changing password: {e}"
    
    def get_user_role(self):
        """Get current user's role"""
        return self.current_user['role'] if self.current_user else None
    
    def require_role(self, required_roles):
        """Check if current user has required role"""
        if not self.current_user:
            return False
        if isinstance(required_roles, str):
            required_roles = [required_roles]
        return self.current_user['role'] in required_roles
    
    def get_all_users(self):
        """Get all users (admin only)"""
        if not self.require_role('admin'):
            return []
        
        try:
            users = self.db.execute_query(
                "SELECT user_id, username, full_name, role, created_date, last_login, is_active FROM users ORDER BY username"
            )
            return [dict(user) for user in users]
        except Exception as e:
            print(f"Error fetching users: {e}")
            return []
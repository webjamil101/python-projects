"""
Authentication and authorization module
"""

import hashlib
import secrets
from typing import Optional, Tuple  # Added Tuple import
from database import DatabaseManager
from models import User

class Authentication:
    """Handles user authentication and authorization"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.current_user = None
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        return hashlib.sha256((password + salt).encode()).hexdigest() + ':' + salt
    
    def verify_password(self, stored_password: str, provided_password: str) -> bool:
        """Verify password against stored hash"""
        try:
            stored_hash, salt = stored_password.split(':')
            computed_hash = hashlib.sha256((provided_password + salt).encode()).hexdigest()
            return secrets.compare_digest(stored_hash, computed_hash)
        except:
            return False
    
    def register_user(self, username: str, password: str, email: str, role: str) -> Tuple[bool, str]:
        """Register a new user"""
        try:
            if role not in ['admin', 'faculty', 'student']:
                return False, "Invalid role"
            
            password_hash = self.hash_password(password)
            
            self.db.execute_query(
                "INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
                (username, password_hash, email, role)
            )
            return True, "User registered successfully"
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """Authenticate user"""
        try:
            result = self.db.fetch_one(
                "SELECT id, username, password_hash, role, email, created_at FROM users WHERE username = ? AND is_active = TRUE",
                (username,)
            )
            
            if not result:
                return False, "User not found", None
            
            user_id, username, stored_hash, role, email, created_at = result
            
            if not self.verify_password(stored_hash, password):
                return False, "Invalid password", None
            
            self.current_user = User(user_id, username, stored_hash, role, email, created_at)
            return True, "Login successful", self.current_user
        except Exception as e:
            return False, f"Login failed: {str(e)}", None
    
    def logout(self):
        """Logout current user"""
        self.current_user = None
        return True, "Logout successful"
    
    def has_permission(self, required_role: str) -> bool:
        """Check if current user has required role"""
        if not self.current_user:
            return False
        return self.current_user.role == required_role or self.current_user.role == 'admin'
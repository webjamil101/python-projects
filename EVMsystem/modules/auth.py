import bcrypt
import secrets
import hashlib
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
            result = self.db.get_single_record(
                "SELECT * FROM administrators WHERE username = ?", 
                ('admin',)
            )
            
            if not result:
                password_hash = self.hash_password('admin123')
                self.db.execute_query('''
                    INSERT INTO administrators (username, password_hash, full_name, role)
                    VALUES (?, ?, ?, ?)
                ''', ('admin', password_hash, 'Election Administrator', 'admin'))
                print("Default admin created: admin/admin123")
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
        """Authenticate administrator"""
        try:
            user = self.db.get_single_record(
                "SELECT * FROM administrators WHERE username = ? AND is_active = 1",
                (username,)
            )
            
            if user and self.verify_password(password, user['password_hash']):
                self.db.execute_query(
                    "UPDATE administrators SET last_login = ? WHERE admin_id = ?",
                    (datetime.now().isoformat(), user['admin_id'])
                )
                
                # Log the login
                self.db.execute_query('''
                    INSERT INTO audit_log (action_type, user_type, user_id, description)
                    VALUES (?, ?, ?, ?)
                ''', ('login', 'admin', user['admin_id'], f"Admin {username} logged in"))
                
                self.current_user = {
                    'admin_id': user['admin_id'],
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
        if self.current_user:
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('logout', 'admin', self.current_user['admin_id'], "Admin logged out"))
        
        self.current_user = None
        return True, "Logged out successfully"
    
    def generate_voter_verification_code(self, voter_id):
        """Generate a unique verification code for voter"""
        code = secrets.token_hex(8).upper()
        self.db.execute_query(
            "UPDATE voters SET verification_code = ? WHERE voter_id = ?",
            (code, voter_id)
        )
        return code
    
    def verify_voter_code(self, voter_card_number, verification_code):
        """Verify voter using verification code"""
        try:
            voter = self.db.get_single_record(
                "SELECT * FROM voters WHERE voter_card_number = ? AND verification_code = ?",
                (voter_card_number, verification_code)
            )
            
            if voter:
                self.db.execute_query(
                    "UPDATE voters SET is_verified = 1, verification_code = NULL WHERE voter_id = ?",
                    (voter['voter_id'],)
                )
                
                self.db.execute_query('''
                    INSERT INTO audit_log (action_type, user_type, user_id, description)
                    VALUES (?, ?, ?, ?)
                ''', ('voter_verification', 'voter', voter['voter_id'], f"Voter {voter_card_number} verified"))
                
                return True, "Voter verified successfully"
            else:
                return False, "Invalid verification code"
                
        except Exception as e:
            return False, f"Verification error: {e}"
    
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
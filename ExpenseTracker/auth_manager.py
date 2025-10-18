import json
import os
import hashlib
import re
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

class AuthManager:
    def __init__(self):
        self.current_user = None
        self.users_file = 'data/users.json'
        self.expenses_dir = 'data/user_expenses'
        self.load_users()
    
    def load_users(self):
        """Load users from JSON file"""
        try:
            os.makedirs('data', exist_ok=True)
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
            else:
                self.users = {}
        except Exception as e:
            print(f"Error loading users: {e}")
            self.users = {}
    
    def save_users(self):
        """Save users to JSON file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save users: {e}")
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def validate_username(self, username):
        """Validate username (alphanumeric, 3-20 characters)"""
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return re.match(pattern, username) is not None
    
    def register_user(self, username, email, password, occupation="Student", base_currency="USD"):
        """Register a new user"""
        # Validate inputs
        if not self.validate_username(username):
            return False, "Username must be 3-20 characters and contain only letters, numbers, and underscores"
        
        if not self.validate_email(email):
            return False, "Please enter a valid email address"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        
        # Check if username or email already exists
        if username in self.users:
            return False, "Username already exists"
        
        for user_data in self.users.values():
            if user_data['email'].lower() == email.lower():
                return False, "Email already registered"
        
        # Create user
        self.users[username] = {
            'email': email,
            'password_hash': self.hash_password(password),
            'occupation': occupation,
            'base_currency': base_currency,
            'monthly_budget': 0,
            'created_at': datetime.now().isoformat(),
            'last_login': datetime.now().isoformat()
        }
        
        # Create user's expense file
        self.create_user_data_file(username)
        
        self.save_users()
        return True, "Registration successful!"
    
    def login_user(self, username, password):
        """Login user"""
        if username not in self.users:
            return False, "Invalid username or password"
        
        user_data = self.users[username]
        
        if user_data['password_hash'] != self.hash_password(password):
            return False, "Invalid username or password"
        
        # Update last login
        user_data['last_login'] = datetime.now().isoformat()
        self.current_user = username
        self.save_users()
        
        return True, f"Welcome back, {username}!"
    
    def logout_user(self):
        """Logout current user"""
        self.current_user = None
    
    def get_current_user_data(self):
        """Get current user's data"""
        if self.current_user and self.current_user in self.users:
            return self.users[self.current_user]
        return None
    
    def update_user_profile(self, occupation, base_currency, monthly_budget):
        """Update user profile"""
        if self.current_user and self.current_user in self.users:
            self.users[self.current_user].update({
                'occupation': occupation,
                'base_currency': base_currency,
                'monthly_budget': float(monthly_budget) if monthly_budget else 0
            })
            self.save_users()
            return True
        return False
    
    def create_user_data_file(self, username):
        """Create user's expense data file"""
        try:
            os.makedirs(self.expenses_dir, exist_ok=True)
            user_file = os.path.join(self.expenses_dir, f"{username}.json")
            if not os.path.exists(user_file):
                with open(user_file, 'w') as f:
                    json.dump({'expenses': []}, f, indent=2)
        except Exception as e:
            print(f"Error creating user data file: {e}")
    
    def get_user_expenses_file(self, username):
        """Get user's expense file path"""
        return os.path.join(self.expenses_dir, f"{username}.json")
    
    def load_user_expenses(self, username):
        """Load user's expenses"""
        try:
            user_file = self.get_user_expenses_file(username)
            if os.path.exists(user_file):
                with open(user_file, 'r') as f:
                    return json.load(f).get('expenses', [])
            return []
        except Exception as e:
            print(f"Error loading user expenses: {e}")
            return []
    
    def save_user_expenses(self, username, expenses):
        """Save user's expenses"""
        try:
            user_file = self.get_user_expenses_file(username)
            with open(user_file, 'w') as f:
                json.dump({'expenses': expenses}, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving user expenses: {e}")
            return False
    
    def get_all_users_stats(self):
        """Get statistics for all users (admin function)"""
        stats = {
            'total_users': len(self.users),
            'users': {}
        }
        
        for username, user_data in self.users.items():
            expenses = self.load_user_expenses(username)
            total_expenses = sum(exp['amount'] for exp in expenses) if expenses else 0
            
            stats['users'][username] = {
                'email': user_data['email'],
                'occupation': user_data['occupation'],
                'total_expenses': total_expenses,
                'expense_count': len(expenses),
                'created_at': user_data['created_at'],
                'last_login': user_data['last_login']
            }
        
        return stats
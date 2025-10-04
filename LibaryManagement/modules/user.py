from .database import DatabaseManager
from .utils import Utilities, ValidationError

class User:
    def __init__(self, user_id=None, name="", email="", phone="", 
                 membership_type="standard", max_books=3):
        self.user_id = user_id or Utilities.generate_id()
        self.name = name
        self.email = email
        self.phone = phone
        self.membership_type = membership_type
        self.membership_status = "active"
        self.max_books = max_books
        self.total_borrowed = 0
        self.date_joined = Utilities.get_current_date()
        
        self.db = DatabaseManager()
    
    def validate_user(self):
        """Validate user data"""
        try:
            Utilities.validate_email(self.email)
            if self.phone:
                Utilities.validate_phone(self.phone)
            return True
        except ValidationError as e:
            raise e
    
    def save(self):
        """Save user to database"""
        self.validate_user()
        
        query = '''
            INSERT OR REPLACE INTO users 
            (user_id, name, email, phone, membership_type, membership_status, 
             max_books, total_borrowed, date_joined)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (self.user_id, self.name, self.email, self.phone,
                 self.membership_type, self.membership_status,
                 self.max_books, self.total_borrowed, self.date_joined)
        
        self.db.execute_query(query, params)
        return self.user_id
    
    def can_borrow_more(self):
        """Check if user can borrow more books"""
        return self.total_borrowed < self.max_books
    
    def update_borrowed_count(self, change):
        """Update user's borrowed book count"""
        self.total_borrowed += change
        query = "UPDATE users SET total_borrowed = ? WHERE user_id = ?"
        self.db.execute_query(query, (self.total_borrowed, self.user_id))

class UserManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def register_user(self, user_data):
        """Register a new user"""
        user = User(**user_data)
        return user.save()
    
    def get_user(self, user_id):
        """Get user by ID"""
        query = "SELECT * FROM users WHERE user_id = ?"
        result = self.db.get_single_record(query, (user_id,))
        return dict(result) if result else None
    
    def get_user_by_email(self, email):
        """Get user by email"""
        query = "SELECT * FROM users WHERE email = ?"
        result = self.db.get_single_record(query, (email,))
        return dict(result) if result else None
    
    def update_user(self, user_id, update_data):
        """Update user information"""
        set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
        query = f"UPDATE users SET {set_clause} WHERE user_id = ?"
        params = list(update_data.values()) + [user_id]
        
        self.db.execute_query(query, params)
        return True
    
    def deactivate_user(self, user_id):
        """Deactivate user account"""
        query = "UPDATE users SET membership_status = 'inactive' WHERE user_id = ?"
        self.db.execute_query(query, (user_id,))
        return True
    
    def get_all_users(self):
        """Get all users"""
        query = "SELECT * FROM users ORDER BY name"
        results = self.db.execute_query(query)
        return [dict(row) for row in results]
    
    def get_user_statistics(self, user_id):
        """Get user borrowing statistics"""
        query = """
            SELECT 
                u.name,
                u.total_borrowed as currently_borrowed,
                u.max_books as max_allowed,
                COUNT(t.transaction_id) as total_borrowed_history,
                SUM(CASE WHEN t.fine_amount > 0 THEN 1 ELSE 0 END) as total_fines,
                SUM(t.fine_amount) as total_fine_amount
            FROM users u
            LEFT JOIN transactions t ON u.user_id = t.user_id
            WHERE u.user_id = ?
            GROUP BY u.user_id
        """
        result = self.db.get_single_record(query, (user_id,))
        return dict(result) if result else None
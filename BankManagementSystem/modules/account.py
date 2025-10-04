from .database import DatabaseManager
from .utils import Utilities, ValidationError

class Account:
    def __init__(self, account_number=None, customer_id="", account_type="savings", 
                 balance=0.0, interest_rate=0.0, overdraft_limit=0.0, minimum_balance=0.0):
        self.account_number = account_number or Utilities.generate_account_number()
        self.customer_id = customer_id
        self.account_type = account_type
        self.balance = balance
        self.interest_rate = interest_rate
        self.overdraft_limit = overdraft_limit
        self.minimum_balance = minimum_balance
        self.opened_date = Utilities.get_current_date()
        self.status = "active"
        
        self.db = DatabaseManager()
    
    def save(self):
        """Save account to database"""
        query = '''
            INSERT INTO accounts 
            (account_number, customer_id, account_type, balance, interest_rate,
             overdraft_limit, minimum_balance, opened_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (self.account_number, self.customer_id, self.account_type,
                 self.balance, self.interest_rate, self.overdraft_limit,
                 self.minimum_balance, self.opened_date, self.status)
        
        self.db.execute_query(query, params)
        return self.account_number
    
    def update_balance(self, amount):
        """Update account balance"""
        self.balance += amount
        query = "UPDATE accounts SET balance = ? WHERE account_number = ?"
        self.db.execute_query(query, (self.balance, self.account_number))
        return self.balance
    
    def can_withdraw(self, amount):
        """Check if withdrawal is allowed"""
        available_balance = self.balance + self.overdraft_limit
        min_balance_after = self.balance - amount
        return amount <= available_balance and min_balance_after >= self.minimum_balance
    
    def to_dict(self):
        """Convert account object to dictionary"""
        return {
            'account_number': self.account_number,
            'customer_id': self.customer_id,
            'account_type': self.account_type,
            'balance': self.balance,
            'interest_rate': self.interest_rate,
            'overdraft_limit': self.overdraft_limit,
            'minimum_balance': self.minimum_balance,
            'opened_date': str(self.opened_date),
            'status': self.status
        }

class AccountManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def create_account(self, account_data):
        """Create a new account"""
        account = Account(**account_data)
        return account.save()
    
    def get_account(self, account_number):
        """Get account by number"""
        query = "SELECT * FROM accounts WHERE account_number = ?"
        result = self.db.get_single_record(query, (account_number,))
        return dict(result) if result else None
    
    def get_customer_accounts(self, customer_id):
        """Get all accounts for a customer"""
        query = """
            SELECT a.*, c.first_name, c.last_name 
            FROM accounts a
            JOIN customers c ON a.customer_id = c.customer_id
            WHERE a.customer_id = ? AND a.status = 'active'
            ORDER BY a.opened_date DESC
        """
        results = self.db.execute_query(query, (customer_id,))
        return [dict(row) for row in results]
    
    def update_account(self, account_number, update_data):
        """Update account information"""
        set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
        query = f"UPDATE accounts SET {set_clause} WHERE account_number = ?"
        params = list(update_data.values()) + [account_number]
        
        self.db.execute_query(query, params)
        return True
    
    def close_account(self, account_number):
        """Close an account"""
        # Check if account has zero balance
        account = self.get_account(account_number)
        if account and account['balance'] != 0:
            return False, "Cannot close account with non-zero balance"
        
        query = "UPDATE accounts SET status = 'closed' WHERE account_number = ?"
        self.db.execute_query(query, (account_number,))
        return True, "Account closed successfully"
    
    def search_accounts(self, **filters):
        """Search accounts with filters"""
        base_query = """
            SELECT a.*, c.first_name, c.last_name, c.email 
            FROM accounts a
            JOIN customers c ON a.customer_id = c.customer_id
            WHERE 1=1
        """
        params = []
        
        if 'account_type' in filters:
            base_query += " AND a.account_type = ?"
            params.append(filters['account_type'])
        
        if 'customer_name' in filters:
            base_query += " AND (c.first_name LIKE ? OR c.last_name LIKE ?)"
            params.extend([f"%{filters['customer_name']}%", f"%{filters['customer_name']}%"])
        
        if 'status' in filters:
            base_query += " AND a.status = ?"
            params.append(filters['status'])
        
        if 'min_balance' in filters:
            base_query += " AND a.balance >= ?"
            params.append(filters['min_balance'])
        
        base_query += " ORDER BY a.balance DESC"
        
        results = self.db.execute_query(base_query, params)
        return [dict(row) for row in results]
    
    def get_account_balance(self, account_number):
        """Get current account balance"""
        account = self.get_account(account_number)
        return account['balance'] if account else 0.0
    
    def apply_interest(self, account_number):
        """Apply interest to account"""
        account = self.get_account(account_number)
        if account and account['interest_rate'] > 0:
            interest = account['balance'] * (account['interest_rate'] / 100) / 12
            new_balance = account['balance'] + interest
            self.update_account(account_number, {'balance': new_balance})
            return interest
        return 0.0
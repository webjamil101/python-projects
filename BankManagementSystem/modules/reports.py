from .database import DatabaseManager
from .utils import Utilities

class ReportGenerator:
    def __init__(self):
        self.db = DatabaseManager()
    
    def get_bank_summary(self):
        """Get overall bank summary"""
        query = """
            SELECT 
                COUNT(DISTINCT customer_id) as total_customers,
                COUNT(*) as total_accounts,
                SUM(balance) as total_deposits,
                AVG(balance) as average_balance,
                COUNT(CASE WHEN account_type = 'savings' THEN 1 END) as savings_accounts,
                COUNT(CASE WHEN account_type = 'checking' THEN 1 END) as checking_accounts
            FROM accounts 
            WHERE status = 'active'
        """
        result = self.db.get_single_record(query)
        return dict(result) if result else {}
    
    def get_daily_transactions(self, date=None):
        """Get daily transaction summary"""
        if date is None:
            date = Utilities.get_current_date()
        
        query = """
            SELECT 
                transaction_type,
                COUNT(*) as transaction_count,
                SUM(amount) as total_amount
            FROM transactions 
            WHERE DATE(transaction_date) = ?
            GROUP BY transaction_type
        """
        results = self.db.execute_query(query, (date,))
        return [dict(row) for row in results]
    
    def get_customer_portfolio(self, customer_id):
        """Get complete customer portfolio"""
        from .account import AccountManager
        from .transaction import TransactionManager
        
        account_manager = AccountManager()
        transaction_manager = TransactionManager()
        
        customer_accounts = account_manager.get_customer_accounts(customer_id)
        portfolio = {
            'accounts': customer_accounts,
            'total_balance': sum(acc['balance'] for acc in customer_accounts),
            'recent_transactions': []
        }
        
        # Get recent transactions for all accounts
        for account in customer_accounts:
            recent_tx = transaction_manager.get_account_transactions(account['account_number'], 5)
            portfolio['recent_transactions'].extend(recent_tx)
        
        # Sort transactions by date
        portfolio['recent_transactions'].sort(key=lambda x: x['transaction_date'], reverse=True)
        
        return portfolio
    
    def get_high_value_accounts(self, min_balance=10000):
        """Get high-value accounts"""
        query = """
            SELECT a.*, c.first_name, c.last_name, c.email
            FROM accounts a
            JOIN customers c ON a.customer_id = c.customer_id
            WHERE a.balance >= ? AND a.status = 'active'
            ORDER BY a.balance DESC
        """
        results = self.db.execute_query(query, (min_balance,))
        return [dict(row) for row in results]
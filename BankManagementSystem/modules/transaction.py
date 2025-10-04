from .database import DatabaseManager
from .utils import Utilities, ValidationError
from datetime import datetime

class Transaction:
    def __init__(self, transaction_id=None, account_number="", transaction_type="", 
                 amount=0.0, description="", balance_after=0.0, related_account=""):
        self.transaction_id = transaction_id or Utilities.generate_id()
        self.account_number = account_number
        self.transaction_type = transaction_type
        self.amount = amount
        self.description = description
        self.transaction_date = Utilities.get_current_date()
        self.balance_after = balance_after
        self.status = "completed"
        self.related_account = related_account
        
        self.db = DatabaseManager()
    
    def save(self):
        """Save transaction to database"""
        query = '''
            INSERT INTO transactions 
            (transaction_id, account_number, transaction_type, amount, description,
             transaction_date, balance_after, status, related_account)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (self.transaction_id, self.account_number, self.transaction_type,
                 self.amount, self.description, self.transaction_date,
                 self.balance_after, self.status, self.related_account)
        
        self.db.execute_query(query, params)
        return self.transaction_id

class TransactionManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def _get_account_manager(self):
        """Lazy import to avoid circular imports"""
        from .account import AccountManager
        return AccountManager()
    
    def deposit(self, account_number, amount, description="Deposit"):
        """Process deposit transaction"""
        account_manager = self._get_account_manager()
        
        try:
            # Validate amount
            amount = Utilities.validate_amount(amount)
        except ValidationError as e:
            return False, str(e)
        
        # Get account
        account = account_manager.get_account(account_number)
        if not account:
            return False, "Account not found"
        
        if account['status'] != 'active':
            return False, "Account is not active"
        
        # Update balance
        new_balance = account['balance'] + amount
        account_manager.update_account(account_number, {'balance': new_balance})
        
        # Record transaction
        transaction = Transaction(
            account_number=account_number,
            transaction_type="deposit",
            amount=amount,
            description=description,
            balance_after=new_balance
        )
        transaction_id = transaction.save()
        
        return True, f"Deposit successful. Transaction ID: {transaction_id}. New Balance: {Utilities.format_currency(new_balance)}"
    
    def withdraw(self, account_number, amount, description="Withdrawal"):
        """Process withdrawal transaction"""
        account_manager = self._get_account_manager()
        
        try:
            # Validate amount
            amount = Utilities.validate_amount(amount)
        except ValidationError as e:
            return False, str(e)
        
        # Get account
        account = account_manager.get_account(account_number)
        if not account:
            return False, "Account not found"
        
        if account['status'] != 'active':
            return False, "Account is not active"
        
        # Check if withdrawal is allowed
        available_balance = account['balance'] + account.get('overdraft_limit', 0)
        min_balance_after = account['balance'] - amount
        minimum_balance = account.get('minimum_balance', 0)
        
        if amount > available_balance:
            return False, "Insufficient funds"
        
        if min_balance_after < minimum_balance:
            return False, f"Withdrawal would bring account below minimum balance of {Utilities.format_currency(minimum_balance)}"
        
        # Update balance
        new_balance = account['balance'] - amount
        account_manager.update_account(account_number, {'balance': new_balance})
        
        # Record transaction
        transaction = Transaction(
            account_number=account_number,
            transaction_type="withdrawal",
            amount=amount,
            description=description,
            balance_after=new_balance
        )
        transaction_id = transaction.save()
        
        return True, f"Withdrawal successful. Transaction ID: {transaction_id}. New Balance: {Utilities.format_currency(new_balance)}"
    
    def transfer(self, from_account, to_account, amount, description="Transfer"):
        """Process transfer between accounts"""
        account_manager = self._get_account_manager()
        
        try:
            # Validate amount
            amount = Utilities.validate_amount(amount)
        except ValidationError as e:
            return False, str(e)
        
        # Check if accounts exist
        from_acc = account_manager.get_account(from_account)
        to_acc = account_manager.get_account(to_account)
        
        if not from_acc:
            return False, "Source account not found"
        if not to_acc:
            return False, "Destination account not found"
        
        if from_acc['status'] != 'active':
            return False, "Source account is not active"
        if to_acc['status'] != 'active':
            return False, "Destination account is not active"
        
        # Check if withdrawal is allowed from source account
        available_balance = from_acc['balance'] + from_acc.get('overdraft_limit', 0)
        min_balance_after = from_acc['balance'] - amount
        minimum_balance = from_acc.get('minimum_balance', 0)
        
        if amount > available_balance:
            return False, "Insufficient funds for transfer"
        
        if min_balance_after < minimum_balance:
            return False, f"Transfer would bring source account below minimum balance of {Utilities.format_currency(minimum_balance)}"
        
        # Process withdrawal from source
        from_new_balance = from_acc['balance'] - amount
        account_manager.update_account(from_account, {'balance': from_new_balance})
        
        # Process deposit to destination
        to_new_balance = to_acc['balance'] + amount
        account_manager.update_account(to_account, {'balance': to_new_balance})
        
        # Record transactions
        # Withdrawal transaction
        withdrawal_transaction = Transaction(
            account_number=from_account,
            transaction_type="transfer_out",
            amount=amount,
            description=f"Transfer to {to_account} - {description}",
            balance_after=from_new_balance,
            related_account=to_account
        )
        withdrawal_transaction.save()
        
        # Deposit transaction
        deposit_transaction = Transaction(
            account_number=to_account,
            transaction_type="transfer_in",
            amount=amount,
            description=f"Transfer from {from_account} - {description}",
            balance_after=to_new_balance,
            related_account=from_account
        )
        deposit_transaction_id = deposit_transaction.save()
        
        return True, f"Transfer successful. Amount: {Utilities.format_currency(amount)}. Transaction ID: {deposit_transaction_id}"
    
    def get_account_transactions(self, account_number, limit=50):
        """Get transaction history for an account"""
        query = """
            SELECT * FROM transactions 
            WHERE account_number = ? 
            ORDER BY transaction_date DESC 
            LIMIT ?
        """
        results = self.db.execute_query(query, (account_number, limit))
        return [dict(row) for row in results]
    
    def get_transaction_history(self, account_number, start_date=None, end_date=None):
        """Get transaction history with date range"""
        base_query = """
            SELECT * FROM transactions 
            WHERE account_number = ?
        """
        params = [account_number]
        
        if start_date:
            base_query += " AND transaction_date >= ?"
            params.append(start_date)
        
        if end_date:
            base_query += " AND transaction_date <= ?"
            params.append(end_date)
        
        base_query += " ORDER BY transaction_date DESC"
        
        results = self.db.execute_query(base_query, params)
        return [dict(row) for row in results]
    
    def get_transaction_by_id(self, transaction_id):
        """Get transaction by ID"""
        query = "SELECT * FROM transactions WHERE transaction_id = ?"
        result = self.db.get_single_record(query, (transaction_id,))
        return dict(result) if result else None
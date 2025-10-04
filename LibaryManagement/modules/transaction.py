from .database import DatabaseManager
from .utils import Utilities, ValidationError
from datetime import datetime

class Transaction:
    def __init__(self, transaction_id=None, user_id="", book_id="", 
                 borrow_date=None, due_date=None, return_date=None, 
                 fine_amount=0, status="borrowed"):
        self.transaction_id = transaction_id or Utilities.generate_id()
        self.user_id = user_id
        self.book_id = book_id
        self.borrow_date = borrow_date or Utilities.get_current_date()
        self.due_date = due_date or Utilities.get_due_date()
        self.return_date = return_date
        self.fine_amount = fine_amount
        self.status = status
        
        self.db = DatabaseManager()
    
    def save(self):
        """Save transaction to database"""
        query = '''
            INSERT INTO transactions 
            (transaction_id, user_id, book_id, borrow_date, due_date, 
             return_date, fine_amount, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (self.transaction_id, self.user_id, self.book_id,
                 self.borrow_date, self.due_date, self.return_date,
                 self.fine_amount, self.status)
        
        self.db.execute_query(query, params)
        return self.transaction_id
    
    def calculate_fine(self):
        """Calculate fine for the transaction"""
        if self.status == "returned" and self.return_date:
            # Handle date conversion
            if isinstance(self.return_date, str):
                return_date = Utilities.format_date(self.return_date)
            else:
                return_date = self.return_date
                
            if isinstance(self.due_date, str):
                due_date = Utilities.format_date(self.due_date)
            else:
                due_date = self.due_date
            
            self.fine_amount = Utilities.calculate_fine(return_date, due_date)
            
            query = "UPDATE transactions SET fine_amount = ? WHERE transaction_id = ?"
            self.db.execute_query(query, (self.fine_amount, self.transaction_id))
            
            return self.fine_amount
        return 0


class TransactionManager:
    def __init__(self):
        self.db = DatabaseManager()
        # Import inside methods to avoid circular imports
    
    def _get_book_manager(self):
        """Lazy import of BookManager to avoid circular imports"""
        from .book import BookManager
        return BookManager()
    
    def _get_user_manager(self):
        """Lazy import of UserManager to avoid circular imports"""
        from .user import UserManager
        return UserManager()
    
    def borrow_book(self, user_id, book_id):
        """Borrow a book"""
        user_manager = self._get_user_manager()
        book_manager = self._get_book_manager()
        
        # Check if user exists and can borrow
        user = user_manager.get_user(user_id)
        if not user:
            return False, "User not found"
        
        if user['total_borrowed'] >= user['max_books']:
            return False, "User has reached maximum borrowing limit"
        
        # Check if book exists and is available
        book = book_manager.get_book_by_id(book_id)
        if not book:
            return False, "Book not found"
        
        if book['available_copies'] <= 0:
            return False, "Book is not available"
        
        # Create transaction
        transaction = Transaction(user_id=user_id, book_id=book_id)
        transaction_id = transaction.save()
        
        # Update book availability
        book_manager.update_availability(book_id, -1)
        
        # Update user borrowed count
        user_manager.update_user(user_id, {'total_borrowed': user['total_borrowed'] + 1})
        
        return True, f"Book borrowed successfully. Transaction ID: {transaction_id}"
    
    def return_book(self, transaction_id):
        """Return a borrowed book"""
        user_manager = self._get_user_manager()
        book_manager = self._get_book_manager()
        
        # Get transaction
        query = "SELECT * FROM transactions WHERE transaction_id = ? AND status = 'borrowed'"
        transaction = self.db.get_single_record(query, (transaction_id,))
        
        if not transaction:
            return False, "Transaction not found or book already returned"
        
        transaction = dict(transaction)
        
        # Update transaction
        return_date = Utilities.get_current_date()
        update_query = """
            UPDATE transactions 
            SET return_date = ?, status = 'returned' 
            WHERE transaction_id = ?
        """
        self.db.execute_query(update_query, (return_date, transaction_id))
        
        # Calculate fine
        transaction_obj = Transaction(**transaction)
        fine_amount = transaction_obj.calculate_fine()
        
        # Update book availability
        book_manager.update_availability(transaction['book_id'], 1)
        
        # Update user borrowed count
        user = user_manager.get_user(transaction['user_id'])
        user_manager.update_user(transaction['user_id'], 
                                {'total_borrowed': user['total_borrowed'] - 1})
        
        message = f"Book returned successfully."
        if fine_amount > 0:
            message += f" Fine amount: ${fine_amount:.2f}"
        
        return True, message
    
    def get_user_transactions(self, user_id):
        """Get all transactions for a user"""
        query = """
            SELECT t.*, b.title, b.author 
            FROM transactions t
            JOIN books b ON t.book_id = b.book_id
            WHERE t.user_id = ?
            ORDER BY t.borrow_date DESC
        """
        results = self.db.execute_query(query, (user_id,))
        return [dict(row) for row in results]
    
    def get_overdue_books(self):
        """Get all overdue books"""
        current_date = Utilities.get_current_date()
        query = """
            SELECT t.*, u.name as user_name, b.title, b.author
            FROM transactions t
            JOIN users u ON t.user_id = u.user_id
            JOIN books b ON t.book_id = b.book_id
            WHERE t.status = 'borrowed' AND t.due_date < ?
            ORDER BY t.due_date
        """
        results = self.db.execute_query(query, (current_date,))
        return [dict(row) for row in results]
    
    def get_transaction_statistics(self):
        """Get transaction statistics"""
        query = """
            SELECT 
                COUNT(*) as total_transactions,
                COUNT(CASE WHEN status = 'borrowed' THEN 1 END) as currently_borrowed,
                COUNT(CASE WHEN status = 'returned' THEN 1 END) as returned_books,
                SUM(fine_amount) as total_fines_collected,
                AVG(fine_amount) as average_fine
            FROM transactions
        """
        result = self.db.get_single_record(query)
        return dict(result) if result else {
            'total_transactions': 0,
            'currently_borrowed': 0,
            'returned_books': 0,
            'total_fines_collected': 0,
            'average_fine': 0
        }
    
    def get_active_transactions(self):
        """Get all active (borrowed) transactions"""
        query = """
            SELECT t.*, u.name as user_name, b.title, b.author
            FROM transactions t
            JOIN users u ON t.user_id = u.user_id
            JOIN books b ON t.book_id = b.book_id
            WHERE t.status = 'borrowed'
            ORDER BY t.due_date
        """
        results = self.db.execute_query(query)
        return [dict(row) for row in results]
    
    def pay_fine(self, transaction_id, amount_paid):
        """Pay fine for a transaction"""
        query = "SELECT fine_amount FROM transactions WHERE transaction_id = ?"
        result = self.db.get_single_record(query, (transaction_id,))
        
        if not result:
            return False, "Transaction not found"
        
        current_fine = result['fine_amount'] or 0
        if amount_paid > current_fine:
            return False, f"Amount paid (${amount_paid:.2f}) exceeds fine amount (${current_fine:.2f})"
        
        new_fine = current_fine - amount_paid
        update_query = "UPDATE transactions SET fine_amount = ? WHERE transaction_id = ?"
        self.db.execute_query(update_query, (new_fine, transaction_id))
        
        return True, f"Fine paid successfully. Remaining fine: ${new_fine:.2f}"
from .database import DatabaseManager
from .utils import Utilities, ValidationError
import json
from datetime import datetime

class Book:
    def __init__(self, book_id=None, title="", author="", isbn="", genre="", 
                 publication_year=0, publisher="", total_copies=1, location=""):
        self.book_id = book_id or Utilities.generate_id()
        self.title = title
        self.author = author
        self.isbn = isbn
        self.genre = genre
        self.publication_year = publication_year
        self.publisher = publisher
        self.total_copies = total_copies
        self.available_copies = total_copies
        self.location = location
        self.status = "available"
        self.date_added = Utilities.get_current_date()
        
        self.db = DatabaseManager()
    
    def save(self):
        """Save book to database"""
        query = '''
            INSERT OR REPLACE INTO books 
            (book_id, title, author, isbn, genre, publication_year, publisher, 
             total_copies, available_copies, location, status, date_added)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (self.book_id, self.title, self.author, self.isbn, self.genre,
                 self.publication_year, self.publisher, self.total_copies,
                 self.available_copies, self.location, self.status, self.date_added)
        
        self.db.execute_query(query, params)
        return self.book_id
    
    def to_dict(self):
        """Convert book object to dictionary"""
        return {
            'book_id': self.book_id,
            'title': self.title,
            'author': self.author,
            'isbn': self.isbn,
            'genre': self.genre,
            'publication_year': self.publication_year,
            'publisher': self.publisher,
            'total_copies': self.total_copies,
            'available_copies': self.available_copies,
            'location': self.location,
            'status': self.status,
            'date_added': str(self.date_added)
        }

class BookManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def add_book(self, book_data):
        """Add a new book to the library"""
        book = Book(**book_data)
        return book.save()
    
    def remove_book(self, book_id):
        """Remove a book from the library"""
        # Check if book is currently borrowed
        query = "SELECT COUNT(*) as count FROM transactions WHERE book_id = ? AND status = 'borrowed'"
        result = self.db.get_single_record(query, (book_id,))
        
        if result and result['count'] > 0:
            return False, "Cannot remove book that is currently borrowed"
        
        query = "DELETE FROM books WHERE book_id = ?"
        self.db.execute_query(query, (book_id,))
        return True, "Book removed successfully"
    
    def update_book(self, book_id, update_data):
        """Update book information"""
        set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
        query = f"UPDATE books SET {set_clause} WHERE book_id = ?"
        params = list(update_data.values()) + [book_id]
        
        self.db.execute_query(query, params)
        return True
    
    def update_availability(self, book_id, change):
        """Update available copies of a book"""
        # First get current availability
        query = "SELECT available_copies, total_copies FROM books WHERE book_id = ?"
        result = self.db.get_single_record(query, (book_id,))
        
        if not result:
            raise ValueError(f"Book with ID {book_id} not found")
        
        new_available = result['available_copies'] + change
        
        # Ensure we don't go below 0 or above total copies
        if new_available < 0:
            new_available = 0
        elif new_available > result['total_copies']:
            new_available = result['total_copies']
        
        status = "available" if new_available > 0 else "unavailable"
        
        update_query = '''
            UPDATE books 
            SET available_copies = ?, status = ?
            WHERE book_id = ?
        '''
        self.db.execute_query(update_query, (new_available, status, book_id))
        return True
    
    def get_book_by_id(self, book_id):
        """Get book by ID"""
        query = "SELECT * FROM books WHERE book_id = ?"
        result = self.db.get_single_record(query, (book_id,))
        return dict(result) if result else None
    
    def search_books(self, **filters):
        """Search books with filters"""
        base_query = "SELECT * FROM books WHERE 1=1"
        params = []
        
        if 'title' in filters:
            base_query += " AND title LIKE ?"
            params.append(f"%{filters['title']}%")
        
        if 'author' in filters:
            base_query += " AND author LIKE ?"
            params.append(f"%{filters['author']}%")
        
        if 'genre' in filters:
            base_query += " AND genre LIKE ?"
            params.append(f"%{filters['genre']}%")
        
        if 'status' in filters:
            base_query += " AND status = ?"
            params.append(filters['status'])
        
        if 'available_only' in filters and filters['available_only']:
            base_query += " AND available_copies > 0"
        
        base_query += " ORDER BY title"
        
        results = self.db.execute_query(base_query, params)
        return [dict(row) for row in results]
    
    def get_all_books(self):
        """Get all books"""
        query = "SELECT * FROM books ORDER BY title"
        results = self.db.execute_query(query)
        return [dict(row) for row in results]
    
    def get_books_statistics(self):
        """Get library statistics"""
        query = """
            SELECT 
                COUNT(*) as total_books,
                SUM(total_copies) as total_copies,
                SUM(available_copies) as available_copies,
                COUNT(CASE WHEN available_copies = 0 THEN 1 END) as unavailable_books
            FROM books
        """
        result = self.db.get_single_record(query)
        return dict(result) if result else {
            'total_books': 0,
            'total_copies': 0,
            'available_copies': 0,
            'unavailable_books': 0
        }
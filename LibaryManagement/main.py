from modules.book import BookManager
from modules.user import UserManager
from modules.transaction import TransactionManager
from modules.utils import Utilities
import json

class LibraryManagementSystem:
    def __init__(self):
        self.book_manager = BookManager()
        self.user_manager = UserManager()
        self.transaction_manager = TransactionManager()
    
    def display_menu(self):
        """Display main menu"""
        print("\n" + "="*50)
        print("      LIBRARY MANAGEMENT SYSTEM")
        print("="*50)
        print("1. Book Management")
        print("2. User Management")
        print("3. Transaction Management")
        print("4. Reports and Statistics")
        print("5. Exit")
        print("="*50)
    
    def book_management_menu(self):
        """Book management submenu"""
        while True:
            print("\n--- Book Management ---")
            print("1. Add New Book")
            print("2. Search Books")
            print("3. View All Books")
            print("4. Update Book")
            print("5. Remove Book")
            print("6. Back to Main Menu")
            
            choice = input("Enter your choice (1-6): ")
            
            if choice == '1':
                self.add_book()
            elif choice == '2':
                self.search_books()
            elif choice == '3':
                self.view_all_books()
            elif choice == '4':
                self.update_book()
            elif choice == '5':
                self.remove_book()
            elif choice == '6':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def user_management_menu(self):
        """User management submenu"""
        while True:
            print("\n--- User Management ---")
            print("1. Register New User")
            print("2. View User Details")
            print("3. View All Users")
            print("4. Update User")
            print("5. Deactivate User")
            print("6. Back to Main Menu")
            
            choice = input("Enter your choice (1-6): ")
            
            if choice == '1':
                self.register_user()
            elif choice == '2':
                self.view_user_details()
            elif choice == '3':
                self.view_all_users()
            elif choice == '4':
                self.update_user()
            elif choice == '5':
                self.deactivate_user()
            elif choice == '6':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def transaction_management_menu(self):
        """Transaction management submenu"""
        while True:
            print("\n--- Transaction Management ---")
            print("1. Borrow Book")
            print("2. Return Book")
            print("3. View User Transactions")
            print("4. View Overdue Books")
            print("5. Back to Main Menu")
            
            choice = input("Enter your choice (1-5): ")
            
            if choice == '1':
                self.borrow_book()
            elif choice == '2':
                self.return_book()
            elif choice == '3':
                self.view_user_transactions()
            elif choice == '4':
                self.view_overdue_books()
            elif choice == '5':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def reports_menu(self):
        """Reports and statistics submenu"""
        while True:
            print("\n--- Reports and Statistics ---")
            print("1. Library Statistics")
            print("2. Transaction Statistics")
            print("3. User Statistics")
            print("4. Back to Main Menu")
            
            choice = input("Enter your choice (1-4): ")
            
            if choice == '1':
                self.library_statistics()
            elif choice == '2':
                self.transaction_statistics()
            elif choice == '3':
                self.user_statistics()
            elif choice == '4':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def add_book(self):
        """Add a new book"""
        print("\n--- Add New Book ---")
        title = input("Enter book title: ")
        author = input("Enter author: ")
        isbn = input("Enter ISBN: ")
        genre = input("Enter genre: ")
        publication_year = input("Enter publication year: ")
        publisher = input("Enter publisher: ")
        total_copies = input("Enter total copies: ")
        location = input("Enter location: ")
        
        book_data = {
            'title': title,
            'author': author,
            'isbn': isbn,
            'genre': genre,
            'publication_year': int(publication_year) if publication_year else 0,
            'publisher': publisher,
            'total_copies': int(total_copies) if total_copies else 1,
            'location': location
        }
        
        book_id = self.book_manager.add_book(book_data)
        print(f"Book added successfully! Book ID: {book_id}")
    
    def search_books(self):
        """Search books"""
        print("\n--- Search Books ---")
        print("Enter search criteria (press enter to skip):")
        title = input("Title: ")
        author = input("Author: ")
        genre = input("Genre: ")
        available_only = input("Show only available books? (y/n): ").lower() == 'y'
        
        filters = {}
        if title: filters['title'] = title
        if author: filters['author'] = author
        if genre: filters['genre'] = genre
        if available_only: filters['available_only'] = True
        
        results = self.book_manager.search_books(**filters)
        
        if results:
            print(f"\nFound {len(results)} books:")
            for book in results:
                status = "Available" if book['available_copies'] > 0 else "Unavailable"
                print(f"ID: {book['book_id']} | {book['title']} by {book['author']} | {status}")
        else:
            print("No books found matching your criteria.")
    
    def view_all_books(self):
        """View all books"""
        books = self.book_manager.get_all_books()
        if books:
            print(f"\nTotal Books: {len(books)}")
            for book in books:
                status = "Available" if book['available_copies'] > 0 else "Unavailable"
                print(f"ID: {book['book_id']} | {book['title']} by {book['author']} | Copies: {book['available_copies']}/{book['total_copies']} | {status}")
        else:
            print("No books in the library.")
    
    def update_book(self):
        """Update book information"""
        book_id = input("Enter book ID to update: ")
        book = self.book_manager.get_book_by_id(book_id)
        
        if not book:
            print("Book not found!")
            return
        
        print(f"\nUpdating book: {book['title']}")
        print("Enter new values (press enter to keep current value):")
        
        updates = {}
        title = input(f"Title [{book['title']}]: ")
        if title: updates['title'] = title
        
        author = input(f"Author [{book['author']}]: ")
        if author: updates['author'] = author
        
        genre = input(f"Genre [{book['genre']}]: ")
        if genre: updates['genre'] = genre
        
        total_copies = input(f"Total Copies [{book['total_copies']}]: ")
        if total_copies: updates['total_copies'] = int(total_copies)
        
        if updates:
            self.book_manager.update_book(book_id, updates)
            print("Book updated successfully!")
        else:
            print("No changes made.")
    
    def remove_book(self):
        """Remove a book"""
        book_id = input("Enter book ID to remove: ")
        success, message = self.book_manager.remove_book(book_id)
        print(message)
    
    def register_user(self):
        """Register a new user"""
        print("\n--- Register New User ---")
        name = input("Enter full name: ")
        email = input("Enter email: ")
        phone = input("Enter phone: ")
        membership_type = input("Enter membership type (standard/premium) [standard]: ") or "standard"
        
        user_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'membership_type': membership_type
        }
        
        try:
            user_id = self.user_manager.register_user(user_data)
            print(f"User registered successfully! User ID: {user_id}")
        except Exception as e:
            print(f"Error: {e}")
    
    def view_user_details(self):
        """View user details"""
        user_id = input("Enter user ID: ")
        user = self.user_manager.get_user(user_id)
        
        if user:
            print(f"\nUser Details:")
            print(f"ID: {user['user_id']}")
            print(f"Name: {user['name']}")
            print(f"Email: {user['email']}")
            print(f"Membership: {user['membership_type']}")
            print(f"Status: {user['membership_status']}")
            print(f"Books Borrowed: {user['total_borrowed']}/{user['max_books']}")
        else:
            print("User not found!")
    
    def view_all_users(self):
        """View all users"""
        users = self.user_manager.get_all_users()
        if users:
            print(f"\nTotal Users: {len(users)}")
            for user in users:
                status = "Active" if user['membership_status'] == 'active' else "Inactive"
                print(f"ID: {user['user_id']} | {user['name']} | {user['email']} | {status}")
        else:
            print("No users registered.")
    
    def update_user(self):
        """Update user information"""
        user_id = input("Enter user ID to update: ")
        user = self.user_manager.get_user(user_id)
        
        if not user:
            print("User not found!")
            return
        
        print(f"\nUpdating user: {user['name']}")
        print("Enter new values (press enter to keep current value):")
        
        updates = {}
        name = input(f"Name [{user['name']}]: ")
        if name: updates['name'] = name
        
        email = input(f"Email [{user['email']}]: ")
        if email: updates['email'] = email
        
        phone = input(f"Phone [{user['phone']}]: ")
        if phone: updates['phone'] = phone
        
        if updates:
            self.user_manager.update_user(user_id, updates)
            print("User updated successfully!")
        else:
            print("No changes made.")
    
    def deactivate_user(self):
        """Deactivate user"""
        user_id = input("Enter user ID to deactivate: ")
        self.user_manager.deactivate_user(user_id)
        print("User deactivated successfully!")
    
    def borrow_book(self):
        """Borrow a book"""
        user_id = input("Enter user ID: ")
        book_id = input("Enter book ID: ")
        
        success, message = self.transaction_manager.borrow_book(user_id, book_id)
        print(message)
    
    def return_book(self):
        """Return a book"""
        transaction_id = input("Enter transaction ID: ")
        success, message = self.transaction_manager.return_book(transaction_id)
        print(message)
    
    def view_user_transactions(self):
        """View user transactions"""
        user_id = input("Enter user ID: ")
        transactions = self.transaction_manager.get_user_transactions(user_id)
        
        if transactions:
            print(f"\nTransaction History for User {user_id}:")
            for trans in transactions:
                status = "Borrowed" if trans['status'] == 'borrowed' else "Returned"
                print(f"TID: {trans['transaction_id']} | {trans['title']} | Borrowed: {trans['borrow_date']} | Status: {status}")
        else:
            print("No transactions found for this user.")
    
    def view_overdue_books(self):
        """View overdue books"""
        overdue_books = self.transaction_manager.get_overdue_books()
        
        if overdue_books:
            print(f"\nOverdue Books ({len(overdue_books)}):")
            for book in overdue_books:
                print(f"User: {book['user_name']} | Book: {book['title']} | Due: {book['due_date']}")
        else:
            print("No overdue books.")
    
    def library_statistics(self):
        """Display library statistics"""
        stats = self.book_manager.get_books_statistics()
        print("\n--- Library Statistics ---")
        print(f"Total Books: {stats['total_books']}")
        print(f"Total Copies: {stats['total_copies']}")
        print(f"Available Copies: {stats['available_copies']}")
        print(f"Unavailable Books: {stats['unavailable_books']}")
    
    def transaction_statistics(self):
        """Display transaction statistics"""
        stats = self.transaction_manager.get_transaction_statistics()
        print("\n--- Transaction Statistics ---")
        print(f"Total Transactions: {stats['total_transactions']}")
        print(f"Currently Borrowed: {stats['currently_borrowed']}")
        print(f"Returned Books: {stats['returned_books']}")
        print(f"Total Fines Collected: ${stats['total_fines_collected'] or 0:.2f}")
    
    def user_statistics(self):
        """Display user statistics"""
        user_id = input("Enter user ID: ")
        stats = self.user_manager.get_user_statistics(user_id)
        
        if stats:
            print(f"\n--- Statistics for {stats['name']} ---")
            print(f"Currently Borrowed: {stats['currently_borrowed']}")
            print(f"Max Allowed: {stats['max_allowed']}")
            print(f"Total Books Borrowed (History): {stats['total_borrowed_history']}")
            print(f"Total Fines: {stats['total_fines']}")
            print(f"Total Fine Amount: ${stats['total_fine_amount'] or 0:.2f}")
        else:
            print("User not found!")
    
    def run(self):
        """Main program loop"""
        print("Welcome to Library Management System!")
        
        while True:
            self.display_menu()
            choice = input("Enter your choice (1-5): ")
            
            if choice == '1':
                self.book_management_menu()
            elif choice == '2':
                self.user_management_menu()
            elif choice == '3':
                self.transaction_management_menu()
            elif choice == '4':
                self.reports_menu()
            elif choice == '5':
                print("Thank you for using Library Management System!")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    library_system = LibraryManagementSystem()
    library_system.run()
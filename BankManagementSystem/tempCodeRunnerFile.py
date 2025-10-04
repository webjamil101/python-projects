from modules.customer import CustomerManager
from modules.account import AccountManager
from modules.transaction import TransactionManager
from modules.reports import ReportGenerator
from modules.utils import Utilities, Security
import getpass

class BankManagementSystem:
    def __init__(self):
        self.customer_manager = CustomerManager()
        self.account_manager = AccountManager()
        self.transaction_manager = TransactionManager()
        self.report_generator = ReportGenerator()
        self.current_user = None
    
    def display_main_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("           ADVANCED BANK MANAGEMENT SYSTEM")
        print("="*60)
        print("1. Customer Management")
        print("2. Account Management")
        print("3. Transaction Processing")
        print("4. Reports and Analytics")
        print("5. System Administration")
        print("6. Exit")
        print("="*60)
    
    def customer_management_menu(self):
        """Customer management submenu"""
        while True:
            print("\n--- Customer Management ---")
            print("1. Register New Customer")
            print("2. Search Customers")
            print("3. View Customer Details")
            print("4. Update Customer Information")
            print("5. Deactivate Customer")
            print("6. Back to Main Menu")
            
            choice = input("Enter your choice (1-6): ")
            
            if choice == '1':
                self.register_customer()
            elif choice == '2':
                self.search_customers()
            elif choice == '3':
                self.view_customer_details()
            elif choice == '4':
                self.update_customer()
            elif choice == '5':
                self.deactivate_customer()
            elif choice == '6':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def account_management_menu(self):
        """Account management submenu"""
        while True:
            print("\n--- Account Management ---")
            print("1. Open New Account")
            print("2. View Account Details")
            print("3. Search Accounts")
            print("4. Close Account")
            print("5. View Account Statement")
            print("6. Back to Main Menu")
            
            choice = input("Enter your choice (1-6): ")
            
            if choice == '1':
                self.open_account()
            elif choice == '2':
                self.view_account_details()
            elif choice == '3':
                self.search_accounts()
            elif choice == '4':
                self.close_account()
            elif choice == '5':
                self.view_account_statement()
            elif choice == '6':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def transaction_menu(self):
        """Transaction processing submenu"""
        while True:
            print("\n--- Transaction Processing ---")
            print("1. Deposit")
            print("2. Withdraw")
            print("3. Transfer Funds")
            print("4. View Transaction History")
            print("5. Back to Main Menu")
            
            choice = input("Enter your choice (1-5): ")
            
            if choice == '1':
                self.process_deposit()
            elif choice == '2':
                self.process_withdrawal()
            elif choice == '3':
                self.process_transfer()
            elif choice == '4':
                self.view_transaction_history()
            elif choice == '5':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def reports_menu(self):
        """Reports and analytics submenu"""
        while True:
            print("\n--- Reports and Analytics ---")
            print("1. Bank Summary")
            print("2. Customer Portfolio")
            print("3. High Value Accounts")
            print("4. Daily Transactions Report")
            print("5. Back to Main Menu")
            
            choice = input("Enter your choice (1-5): ")
            
            if choice == '1':
                self.show_bank_summary()
            elif choice == '2':
                self.show_customer_portfolio()
            elif choice == '3':
                self.show_high_value_accounts()
            elif choice == '4':
                self.show_daily_transactions()
            elif choice == '5':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def register_customer(self):
        """Register a new customer"""
        print("\n--- Register New Customer ---")
        first_name = input("First Name: ")
        last_name = input("Last Name: ")
        email = input("Email: ")
        phone = input("Phone: ")
        address = input("Address: ")
        date_of_birth = input("Date of Birth (YYYY-MM-DD): ")
        id_type = input("ID Type (passport/driving_license/national_id): ")
        id_number = input("ID Number: ")
        
        customer_data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone': phone,
            'address': address,
            'date_of_birth': date_of_birth,
            'id_type': id_type,
            'id_number': id_number
        }
        
        try:
            customer_id = self.customer_manager.create_customer(customer_data)
            print(f"Customer registered successfully! Customer ID: {customer_id}")
        except Exception as e:
            print(f"Error: {e}")
    
    def open_account(self):
        """Open a new account"""
        print("\n--- Open New Account ---")
        customer_id = input("Customer ID: ")
        
        # Verify customer exists
        customer = self.customer_manager.get_customer(customer_id)
        if not customer:
            print("Customer not found!")
            return
        
        print(f"Customer: {customer['first_name']} {customer['last_name']}")
        account_type = input("Account Type (savings/checking/business): ")
        
        # Set account parameters based on type
        account_data = {
            'customer_id': customer_id,
            'account_type': account_type,
            'balance': 0.0
        }
        
        if account_type == 'savings':
            account_data['interest_rate'] = 1.5
            account_data['minimum_balance'] = 100.0
        elif account_type == 'checking':
            account_data['overdraft_limit'] = 500.0
            account_data['minimum_balance'] = 50.0
        
        initial_deposit = input("Initial Deposit Amount: ")
        if initial_deposit:
            try:
                account_data['balance'] = Utilities.validate_amount(initial_deposit)
            except ValueError as e:
                print(f"Error: {e}")
                return
        
        account_number = self.account_manager.create_account(account_data)
        print(f"Account opened successfully! Account Number: {account_number}")
    
    def process_deposit(self):
        """Process deposit transaction"""
        print("\n--- Process Deposit ---")
        account_number = input("Account Number: ")
        amount = input("Amount: ")
        
        success, message = self.transaction_manager.deposit(account_number, amount)
        print(message)
    
    def process_withdrawal(self):
        """Process withdrawal transaction"""
        print("\n--- Process Withdrawal ---")
        account_number = input("Account Number: ")
        amount = input("Amount: ")
        
        success, message = self.transaction_manager.withdraw(account_number, amount)
        print(message)
    
    def process_transfer(self):
        """Process fund transfer"""
        print("\n--- Transfer Funds ---")
        from_account = input("From Account: ")
        to_account = input("To Account: ")
        amount = input("Amount: ")
        description = input("Description: ")
        
        success, message = self.transaction_manager.transfer(from_account, to_account, amount, description)
        print(message)
    
    def show_bank_summary(self):
        """Display bank summary report"""
        print("\n--- Bank Summary ---")
        summary = self.report_generator.get_bank_summary()
        
        if summary:
            print(f"Total Customers: {summary.get('total_customers', 0)}")
            print(f"Total Accounts: {summary.get('total_accounts', 0)}")
            print(f"Total Deposits: {Utilities.format_currency(summary.get('total_deposits', 0))}")
            print(f"Average Balance: {Utilities.format_currency(summary.get('average_balance', 0))}")
            print(f"Savings Accounts: {summary.get('savings_accounts', 0)}")
            print(f"Checking Accounts: {summary.get('checking_accounts', 0)}")
        else:
            print("No data available.")
    
    def search_customers(self):
        """Search for customers"""
        print("\n--- Search Customers ---")
        print("Enter search criteria (press enter to skip):")
        name = input("Name: ")
        email = input("Email: ")
        phone = input("Phone: ")
        
        filters = {}
        if name: filters['name'] = name
        if email: filters['email'] = email
        if phone: filters['phone'] = phone
        
        results = self.customer_manager.search_customers(**filters)
        
        if results:
            print(f"\nFound {len(results)} customers:")
            for customer in results:
                status = "Active" if customer['status'] == 'active' else "Inactive"
                print(f"ID: {customer['customer_id']} | {customer['first_name']} {customer['last_name']} | {customer['email']} | {status}")
        else:
            print("No customers found matching your criteria.")
    
    def view_customer_details(self):
        """View customer details"""
        customer_id = input("Enter Customer ID: ")
        customer = self.customer_manager.get_customer(customer_id)
        
        if customer:
            print(f"\nCustomer Details:")
            print(f"ID: {customer['customer_id']}")
            print(f"Name: {customer['first_name']} {customer['last_name']}")
            print(f"Email: {customer['email']}")
            print(f"Phone: {customer['phone']}")
            print(f"Address: {customer['address']}")
            print(f"Status: {customer['status']}")
            
            # Show customer's accounts
            accounts = self.account_manager.get_customer_accounts(customer_id)
            if accounts:
                print(f"\nAccounts:")
                for account in accounts:
                    print(f"  {account['account_number']} - {account['account_type']} - Balance: {Utilities.format_currency(account['balance'])}")
        else:
            print("Customer not found!")
    
    def run(self):
        """Main program loop"""
        print("Welcome to Advanced Bank Management System!")
        
        while True:
            self.display_main_menu()
            choice = input("Enter your choice (1-6): ")
            
            if choice == '1':
                self.customer_management_menu()
            elif choice == '2':
                self.account_management_menu()
            elif choice == '3':
                self.transaction_menu()
            elif choice == '4':
                self.reports_menu()
            elif choice == '5':
                self.system_admin_menu()
            elif choice == '6':
                print("Thank you for using Bank Management System!")
                break
            else:
                print("Invalid choice. Please try again.")
    
    def system_admin_menu(self):
        """System administration menu"""
        print("\nSystem Administration features coming soon...")

if __name__ == "__main__":
    try:
        bank_system = BankManagementSystem()
        bank_system.run()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
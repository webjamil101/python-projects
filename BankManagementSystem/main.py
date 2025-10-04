from modules.customer import CustomerManager
from modules.account import AccountManager
from modules.transaction import TransactionManager
from modules.reports import ReportGenerator
from modules.utils import Utilities, ValidationError
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
        print("5. Exit")
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
            print("6. View All Customers")
            print("7. Back to Main Menu")
            
            choice = input("Enter your choice (1-7): ")
            
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
                self.view_all_customers()
            elif choice == '7':
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
            print("6. View Customer Accounts")
            print("7. Back to Main Menu")
            
            choice = input("Enter your choice (1-7): ")
            
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
                self.view_customer_accounts()
            elif choice == '7':
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
            print(f"✓ Customer registered successfully! Customer ID: {customer_id}")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def open_account(self):
        """Open a new account"""
        print("\n--- Open New Account ---")
        customer_id = input("Customer ID: ")
        
        # Verify customer exists
        customer = self.customer_manager.get_customer(customer_id)
        if not customer:
            print("✗ Customer not found!")
            return
        
        print(f"Customer: {customer['first_name']} {customer['last_name']}")
        account_type = input("Account Type (savings/checking): ")
        
        if account_type not in ['savings', 'checking']:
            print("✗ Invalid account type. Choose 'savings' or 'checking'")
            return
        
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
        
        initial_deposit = input("Initial Deposit Amount (optional): ")
        if initial_deposit:
            try:
                account_data['balance'] = Utilities.validate_amount(initial_deposit)
            except ValidationError as e:
                print(f"✗ Error: {e}")
                return
        
        try:
            account_number = self.account_manager.create_account(account_data)
            print(f"✓ Account opened successfully! Account Number: {account_number}")
            if initial_deposit:
                print(f"Initial deposit: {Utilities.format_currency(float(initial_deposit))}")
        except Exception as e:
            print(f"✗ Error opening account: {e}")
    
    def process_deposit(self):
        """Process deposit transaction"""
        print("\n--- Process Deposit ---")
        account_number = input("Account Number: ")
        amount = input("Amount: ")
        description = input("Description (optional): ") or "Deposit"
        
        success, message = self.transaction_manager.deposit(account_number, amount, description)
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
    
    def process_withdrawal(self):
        """Process withdrawal transaction"""
        print("\n--- Process Withdrawal ---")
        account_number = input("Account Number: ")
        amount = input("Amount: ")
        description = input("Description (optional): ") or "Withdrawal"
        
        success, message = self.transaction_manager.withdraw(account_number, amount, description)
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
    
    def process_transfer(self):
        """Process fund transfer"""
        print("\n--- Transfer Funds ---")
        from_account = input("From Account: ")
        to_account = input("To Account: ")
        amount = input("Amount: ")
        description = input("Description (optional): ") or "Transfer"
        
        success, message = self.transaction_manager.transfer(from_account, to_account, amount, description)
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
    
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
            print(f"\n--- Customer Details ---")
            print(f"ID: {customer['customer_id']}")
            print(f"Name: {customer['first_name']} {customer['last_name']}")
            print(f"Email: {customer['email']}")
            print(f"Phone: {customer['phone']}")
            print(f"Address: {customer['address']}")
            print(f"Date of Birth: {customer['date_of_birth']}")
            print(f"ID Type: {customer['id_type']}")
            print(f"ID Number: {customer['id_number']}")
            print(f"Status: {customer['status']}")
            print(f"Joined: {customer['created_date']}")
        else:
            print("✗ Customer not found!")
    
    def view_all_customers(self):
        """View all customers"""
        customers = self.customer_manager.get_all_customers()
        if customers:
            print(f"\n--- All Customers ({len(customers)}) ---")
            for customer in customers:
                status = "Active" if customer['status'] == 'active' else "Inactive"
                print(f"ID: {customer['customer_id']} | {customer['first_name']} {customer['last_name']} | {customer['email']} | {status}")
        else:
            print("No customers found.")
    
    def view_account_details(self):
        """View account details"""
        account_number = input("Enter Account Number: ")
        account = self.account_manager.get_account(account_number)
        
        if account:
            customer = self.customer_manager.get_customer(account['customer_id'])
            print(f"\n--- Account Details ---")
            print(f"Account Number: {account['account_number']}")
            print(f"Customer: {customer['first_name']} {customer['last_name']}")
            print(f"Account Type: {account['account_type']}")
            print(f"Balance: {Utilities.format_currency(account['balance'])}")
            print(f"Interest Rate: {account['interest_rate']}%")
            print(f"Overdraft Limit: {Utilities.format_currency(account.get('overdraft_limit', 0))}")
            print(f"Minimum Balance: {Utilities.format_currency(account.get('minimum_balance', 0))}")
            print(f"Status: {account['status']}")
            print(f"Opened: {account['opened_date']}")
        else:
            print("✗ Account not found!")
    
    def view_customer_accounts(self):
        """View all accounts for a customer"""
        customer_id = input("Enter Customer ID: ")
        accounts = self.account_manager.get_customer_accounts(customer_id)
        
        if accounts:
            customer = self.customer_manager.get_customer(customer_id)
            print(f"\n--- Accounts for {customer['first_name']} {customer['last_name']} ---")
            for account in accounts:
                print(f"Account: {account['account_number']} | Type: {account['account_type']} | Balance: {Utilities.format_currency(account['balance'])} | Status: {account['status']}")
        else:
            print("No accounts found for this customer.")
    
    def search_accounts(self):
        """Search accounts"""
        print("\n--- Search Accounts ---")
        print("Enter search criteria (press enter to skip):")
        account_type = input("Account Type (savings/checking): ")
        customer_name = input("Customer Name: ")
        min_balance = input("Minimum Balance: ")
        
        filters = {}
        if account_type: filters['account_type'] = account_type
        if customer_name: filters['customer_name'] = customer_name
        if min_balance:
            try:
                filters['min_balance'] = float(min_balance)
            except ValueError:
                print("Invalid minimum balance amount")
                return
        
        results = self.account_manager.search_accounts(**filters)
        
        if results:
            print(f"\nFound {len(results)} accounts:")
            for account in results:
                print(f"Account: {account['account_number']} | {account['first_name']} {account['last_name']} | {account['account_type']} | Balance: {Utilities.format_currency(account['balance'])}")
        else:
            print("No accounts found matching your criteria.")
    
    def close_account(self):
        """Close an account"""
        account_number = input("Enter Account Number to close: ")
        success, message = self.account_manager.close_account(account_number)
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
    
    def view_account_statement(self):
        """View account statement"""
        account_number = input("Enter Account Number: ")
        limit = input("Number of transactions to show (default 20): ") or "20"
        
        try:
            limit = int(limit)
        except ValueError:
            print("Invalid number")
            return
        
        transactions = self.transaction_manager.get_account_transactions(account_number, limit)
        
        if transactions:
            account = self.account_manager.get_account(account_number)
            if account:
                print(f"\n--- Account Statement for {account_number} ---")
                print(f"Current Balance: {Utilities.format_currency(account['balance'])}\n")
                
                for tx in transactions:
                    amount_str = Utilities.format_currency(tx['amount'])
                    if tx['transaction_type'] in ['withdrawal', 'transfer_out']:
                        amount_str = f"-{amount_str}"
                    else:
                        amount_str = f"+{amount_str}"
                    
                    print(f"{tx['transaction_date']} | {tx['transaction_type'].upper():<12} | {amount_str:>15} | {tx['description']}")
            else:
                print("Account not found")
        else:
            print("No transactions found for this account.")
    
    def view_transaction_history(self):
        """View transaction history"""
        account_number = input("Enter Account Number: ")
        transactions = self.transaction_manager.get_account_transactions(account_number, 50)
        
        if transactions:
            print(f"\n--- Recent Transactions for {account_number} ---")
            for tx in transactions:
                amount_str = Utilities.format_currency(tx['amount'])
                if tx['transaction_type'] in ['withdrawal', 'transfer_out']:
                    amount_str = f"-{amount_str}"
                else:
                    amount_str = f"+{amount_str}"
                
                print(f"ID: {tx['transaction_id']} | {tx['transaction_date']} | {tx['transaction_type']} | {amount_str} | Balance: {Utilities.format_currency(tx['balance_after'])}")
        else:
            print("No transactions found for this account.")
    
    def show_customer_portfolio(self):
        """Show customer portfolio"""
        customer_id = input("Enter Customer ID: ")
        portfolio = self.report_generator.get_customer_portfolio(customer_id)
        
        if portfolio and portfolio['accounts']:
            customer = self.customer_manager.get_customer(customer_id)
            print(f"\n--- Portfolio for {customer['first_name']} {customer['last_name']} ---")
            print(f"Total Balance: {Utilities.format_currency(portfolio['total_balance'])}")
            print(f"Number of Accounts: {len(portfolio['accounts'])}")
            
            print(f"\nAccounts:")
            for account in portfolio['accounts']:
                print(f"  {account['account_number']} - {account['account_type']} - {Utilities.format_currency(account['balance'])}")
            
            if portfolio['recent_transactions']:
                print(f"\nRecent Transactions:")
                for tx in portfolio['recent_transactions'][:10]:  # Show last 10 transactions
                    amount_str = Utilities.format_currency(tx['amount'])
                    if tx['transaction_type'] in ['withdrawal', 'transfer_out']:
                        amount_str = f"-{amount_str}"
                    print(f"  {tx['transaction_date']} - {tx['transaction_type']} - {amount_str} - {tx['description']}")
        else:
            print("No portfolio data found for this customer.")
    
    def show_high_value_accounts(self):
        """Show high value accounts"""
        min_balance = input("Minimum balance (default 10000): ") or "10000"
        
        try:
            min_balance = float(min_balance)
        except ValueError:
            print("Invalid amount")
            return
        
        accounts = self.report_generator.get_high_value_accounts(min_balance)
        
        if accounts:
            print(f"\n--- High Value Accounts (Balance >= {Utilities.format_currency(min_balance)}) ---")
            for account in accounts:
                print(f"Account: {account['account_number']} | {account['first_name']} {account['last_name']} | {account['account_type']} | Balance: {Utilities.format_currency(account['balance'])}")
        else:
            print(f"No accounts found with balance >= {Utilities.format_currency(min_balance)}")
    
    def show_daily_transactions(self):
        """Show daily transactions report"""
        date = input("Enter date (YYYY-MM-DD) or press enter for today: ")
        if not date:
            date = Utilities.get_current_date()
        
        transactions = self.report_generator.get_daily_transactions(date)
        
        if transactions:
            print(f"\n--- Daily Transactions Report for {date} ---")
            total_amount = 0
            for tx_type in transactions:
                print(f"{tx_type['transaction_type']}: {tx_type['transaction_count']} transactions, Total: {Utilities.format_currency(tx_type['total_amount'])}")
                total_amount += tx_type['total_amount']
            print(f"Grand Total: {Utilities.format_currency(total_amount)}")
        else:
            print(f"No transactions found for {date}")
    
    def update_customer(self):
        """Update customer information"""
        customer_id = input("Enter Customer ID to update: ")
        customer = self.customer_manager.get_customer(customer_id)
        
        if not customer:
            print("✗ Customer not found!")
            return
        
        print(f"\nUpdating customer: {customer['first_name']} {customer['last_name']}")
        print("Enter new values (press enter to keep current value):")
        
        updates = {}
        first_name = input(f"First Name [{customer['first_name']}]: ")
        if first_name: updates['first_name'] = first_name
        
        last_name = input(f"Last Name [{customer['last_name']}]: ")
        if last_name: updates['last_name'] = last_name
        
        email = input(f"Email [{customer['email']}]: ")
        if email: updates['email'] = email
        
        phone = input(f"Phone [{customer['phone']}]: ")
        if phone: updates['phone'] = phone
        
        address = input(f"Address [{customer['address']}]: ")
        if address: updates['address'] = address
        
        if updates:
            try:
                self.customer_manager.update_customer(customer_id, updates)
                print("✓ Customer updated successfully!")
            except Exception as e:
                print(f"✗ Error updating customer: {e}")
        else:
            print("No changes made.")
    
    def deactivate_customer(self):
        """Deactivate customer"""
        customer_id = input("Enter Customer ID to deactivate: ")
        customer = self.customer_manager.get_customer(customer_id)
        
        if not customer:
            print("✗ Customer not found!")
            return
        
        confirm = input(f"Are you sure you want to deactivate {customer['first_name']} {customer['last_name']}? (y/n): ")
        if confirm.lower() == 'y':
            self.customer_manager.deactivate_customer(customer_id)
            print("✓ Customer deactivated successfully!")
        else:
            print("Deactivation cancelled.")
    
    def run(self):
        """Main program loop"""
        print("🚀 Welcome to Advanced Bank Management System!")
        
        while True:
            self.display_main_menu()
            choice = input("Enter your choice (1-5): ")
            
            if choice == '1':
                self.customer_management_menu()
            elif choice == '2':
                self.account_management_menu()
            elif choice == '3':
                self.transaction_menu()
            elif choice == '4':
                self.reports_menu()
            elif choice == '5':
                print("Thank you for using Bank Management System! Goodbye! 👋")
                break
            else:
                print("✗ Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        bank_system = BankManagementSystem()
        bank_system.run()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye! 👋")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
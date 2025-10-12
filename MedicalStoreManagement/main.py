import os
import sys
from datetime import datetime, timedelta
from colorama import Fore, Style, init

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from modules.auth import Authentication
from modules.medicine import MedicineManager
from modules.supplier import SupplierManager
from modules.customer import CustomerManager
from modules.sales import SalesManager
from modules.inventory import InventoryManager
from modules.reports import ReportGenerator

# Initialize colorama
init(autoreset=True)

class MedicalStoreManagementSystem:
    def __init__(self):
        self.auth = Authentication()
        self.medicine_manager = MedicineManager()
        self.supplier_manager = SupplierManager()
        self.customer_manager = CustomerManager()
        self.sales_manager = SalesManager()
        self.inventory_manager = InventoryManager()
        self.report_generator = ReportGenerator()
    
    def display_header(self):
        """Display program header"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.CYAN + "=" * 70)
        print(Fore.YELLOW + "🏥 MEDICAL STORE MANAGEMENT SYSTEM")
        print(Fore.CYAN + "=" * 70)
        print(Fore.WHITE + "A comprehensive pharmacy management solution")
        if self.auth.current_user:
            print(Fore.GREEN + f"Logged in as: {self.auth.current_user['full_name']} ({self.auth.current_user['role']})")
        print(Fore.CYAN + "=" * 70)
    
    def display_main_menu(self):
        """Display main menu based on user role"""
        print(f"\n{Fore.GREEN}📋 MAIN MENU")
        print(Fore.CYAN + "-" * 50)
        
        # Common menu items for all roles
        print(f"{Fore.YELLOW}1. 💊 Medicine Management")
        print(f"{Fore.YELLOW}2. 🛒 Sales Management")
        print(f"{Fore.YELLOW}3. 📦 Inventory Management")
        print(f"{Fore.YELLOW}4. 📊 Reports & Analytics")
        
        # Role-specific menu items
        if self.auth.require_role(['admin', 'manager']):
            print(f"{Fore.YELLOW}5. 👥 Customer Management")
            print(f"{Fore.YELLOW}6. 🏢 Supplier Management")
        
        if self.auth.require_role('admin'):
            print(f"{Fore.YELLOW}7. 👤 User Management")
        
        print(f"{Fore.YELLOW}8. ⚙️  Settings")
        print(f"{Fore.YELLOW}9. 🚪 Logout")
        print(Fore.CYAN + "-" * 50)
    
    def login_menu(self):
        """Handle user login"""
        while True:
            self.display_header()
            print(f"\n{Fore.GREEN}🔐 LOGIN")
            print(Fore.CYAN + "-" * 30)
            
            username = input(f"{Fore.WHITE}Username: ")
            password = input(f"{Fore.WHITE}Password: ")
            
            success, message = self.auth.login(username, password)
            
            if success:
                print(f"\n{Fore.GREEN}✅ {message}")
                input(f"{Fore.WHITE}Press Enter to continue...")
                return True
            else:
                print(f"\n{Fore.RED}❌ {message}")
                retry = input(f"\n{Fore.WHITE}Try again? (y/n): ").lower()
                if retry != 'y':
                    return False
    
    def medicine_management_menu(self):
        """Medicine management submenu"""
        while True:
            self.display_header()
            print(f"\n{Fore.GREEN}💊 MEDICINE MANAGEMENT")
            print(Fore.CYAN + "-" * 50)
            print(f"{Fore.YELLOW}1. ➕ Add New Medicine")
            print(f"{Fore.YELLOW}2. 📝 Update Medicine")
            print(f"{Fore.YELLOW}3. 🔍 Search Medicines")
            print(f"{Fore.YELLOW}4. 📋 View All Medicines")
            print(f"{Fore.YELLOW}5. 📉 Low Stock Alert")
            print(f"{Fore.YELLOW}6. ⚠️  Expiry Alert")
            print(f"{Fore.YELLOW}7. ↩️  Back to Main Menu")
            print(Fore.CYAN + "-" * 50)
            
            choice = input(f"{Fore.WHITE}Enter your choice (1-7): ").strip()
            
            if choice == '1':
                self.add_medicine()
            elif choice == '2':
                self.update_medicine()
            elif choice == '3':
                self.search_medicines()
            elif choice == '4':
                self.view_all_medicines()
            elif choice == '5':
                self.low_stock_alert()
            elif choice == '6':
                self.expiry_alert()
            elif choice == '7':
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")
                input("Press Enter to continue...")
    
    def add_medicine(self):
        """Add a new medicine"""
        print(f"\n{Fore.GREEN}➕ ADD NEW MEDICINE")
        print(Fore.CYAN + "-" * 50)
        
        medicine_data = {}
        medicine_data['name'] = input("Medicine Name: ")
        medicine_data['generic_name'] = input("Generic Name (optional): ")
        medicine_data['batch_number'] = input("Batch Number: ")
        medicine_data['manufacturer'] = input("Manufacturer: ")
        medicine_data['category'] = input("Category: ")
        medicine_data['price'] = input("Selling Price: ")
        medicine_data['cost_price'] = input("Cost Price: ")
        medicine_data['quantity'] = input("Initial Quantity: ")
        medicine_data['reorder_level'] = input("Reorder Level: ")
        medicine_data['expiry_date'] = input("Expiry Date (YYYY-MM-DD): ")
        medicine_data['description'] = input("Description (optional): ")
        
        success, message = self.medicine_manager.add_medicine(medicine_data)
        
        if success:
            print(f"\n{Fore.GREEN}✅ {message}")
        else:
            print(f"\n{Fore.RED}❌ {message}")
        
        input("Press Enter to continue...")
    
    def view_all_medicines(self):
        """View all medicines"""
        medicines = self.medicine_manager.get_all_medicines()
        
        print(f"\n{Fore.GREEN}📋 ALL MEDICINES")
        print(Fore.CYAN + "-" * 100)
        print(f"{'ID':<4} {'Name':<20} {'Batch':<12} {'Qty':<6} {'Price':<8} {'Expiry':<12}")
        print(Fore.CYAN + "-" * 100)
        
        for med in medicines:
            print(f"{med['medicine_id']:<4} {med['name']:<20} {med['batch_number']:<12} {med['quantity']:<6} ${med['price']:<7.2f} {med['expiry_date']:<12}")
        
        print(Fore.CYAN + "-" * 100)
        input("Press Enter to continue...")
    
    def low_stock_alert(self):
        """Show low stock medicines"""
        medicines = self.medicine_manager.get_low_stock_medicines()
        
        print(f"\n{Fore.RED}📉 LOW STOCK ALERT")
        print(Fore.CYAN + "-" * 100)
        
        if not medicines:
            print(f"{Fore.GREEN}✅ No low stock items!")
        else:
            print(f"{'ID':<4} {'Name':<20} {'Batch':<12} {'Qty':<6} {'Reorder Level':<13}")
            print(Fore.CYAN + "-" * 100)
            for med in medicines:
                print(f"{med['medicine_id']:<4} {med['name']:<20} {med['batch_number']:<12} {med['quantity']:<6} {med['reorder_level']:<13}")
        
        print(Fore.CYAN + "-" * 100)
        input("Press Enter to continue...")
    
    def sales_management_menu(self):
        """Sales management submenu"""
        while True:
            self.display_header()
            print(f"\n{Fore.GREEN}🛒 SALES MANAGEMENT")
            print(Fore.CYAN + "-" * 50)
            print(f"{Fore.YELLOW}1. 💰 Create New Sale")
            print(f"{Fore.YELLOW}2. 📜 View Sales History")
            print(f"{Fore.YELLOW}3. 📈 Daily Sales Summary")
            print(f"{Fore.YELLOW}4. ↩️  Back to Main Menu")
            print(Fore.CYAN + "-" * 50)
            
            choice = input(f"{Fore.WHITE}Enter your choice (1-4): ").strip()
            
            if choice == '1':
                self.create_sale()
            elif choice == '2':
                self.view_sales_history()
            elif choice == '3':
                self.daily_sales_summary()
            elif choice == '4':
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")
                input("Press Enter to continue...")
    
    def create_sale(self):
        """Create a new sale"""
        print(f"\n{Fore.GREEN}💰 CREATE NEW SALE")
        print(Fore.CYAN + "-" * 50)
        
        # Show available medicines
        medicines = self.medicine_manager.get_all_medicines()
        print("Available Medicines:")
        print(f"{'ID':<4} {'Name':<20} {'Price':<8} {'Stock':<6}")
        print("-" * 50)
        for med in medicines:
            print(f"{med['medicine_id']:<4} {med['name']:<20} ${med['price']:<7.2f} {med['quantity']:<6}")
        
        sale_data = {
            'items': [],
            'total_amount': 0,
            'discount': 0,
            'tax_amount': 0,
            'final_amount': 0
        }
        
        # Add items to sale
        while True:
            try:
                medicine_id = input("\nEnter Medicine ID (0 to finish): ")
                if medicine_id == '0':
                    break
                
                quantity = int(input("Enter Quantity: "))
                
                # Find medicine
                medicine = self.medicine_manager.get_medicine(int(medicine_id))
                if not medicine:
                    print(f"{Fore.RED}Medicine not found!")
                    continue
                
                if quantity > medicine['quantity']:
                    print(f"{Fore.RED}Insufficient stock! Available: {medicine['quantity']}")
                    continue
                
                total_price = quantity * medicine['price']
                sale_data['items'].append({
                    'medicine_id': int(medicine_id),
                    'quantity': quantity,
                    'unit_price': medicine['price'],
                    'total_price': total_price
                })
                
                sale_data['total_amount'] += total_price
                print(f"Added: {medicine['name']} x {quantity} = ${total_price:.2f}")
                
            except ValueError:
                print(f"{Fore.RED}Invalid input!")
        
        if not sale_data['items']:
            print(f"{Fore.YELLOW}No items added. Sale cancelled.")
            input("Press Enter to continue...")
            return
        
        # Calculate final amount
        sale_data['discount'] = float(input("Enter Discount Amount: ") or "0")
        sale_data['tax_amount'] = sale_data['total_amount'] * 0.05  # 5% tax
        sale_data['final_amount'] = sale_data['total_amount'] - sale_data['discount'] + sale_data['tax_amount']
        
        # Customer information
        customer_id = input("Enter Customer ID (optional): ")
        if customer_id:
            sale_data['customer_id'] = int(customer_id)
        
        sale_data['payment_method'] = input("Payment Method (cash/card): ") or "cash"
        
        # Confirm sale
        print(f"\n{Fore.CYAN}SALE SUMMARY")
        print(f"Total Amount: ${sale_data['total_amount']:.2f}")
        print(f"Discount: ${sale_data['discount']:.2f}")
        print(f"Tax: ${sale_data['tax_amount']:.2f}")
        print(f"Final Amount: ${sale_data['final_amount']:.2f}")
        
        confirm = input("\nConfirm sale? (y/n): ").lower()
        if confirm == 'y':
            success, message = self.sales_manager.create_sale(sale_data, self.auth.current_user['user_id'])
            if success:
                print(f"\n{Fore.GREEN}✅ {message}")
            else:
                print(f"\n{Fore.RED}❌ {message}")
        else:
            print(f"{Fore.YELLOW}Sale cancelled.")
        
        input("Press Enter to continue...")
    
    def inventory_management_menu(self):
        """Inventory management submenu"""
        while True:
            self.display_header()
            print(f"\n{Fore.GREEN}📦 INVENTORY MANAGEMENT")
            print(Fore.CYAN + "-" * 50)
            print(f"{Fore.YELLOW}1. 📊 Inventory Status")
            print(f"{Fore.YELLOW}2. 📈 Stock Movements")
            print(f"{Fore.YELLOW}3. 💰 Inventory Valuation")
            print(f"{Fore.YELLOW}4. ↩️  Back to Main Menu")
            print(Fore.CYAN + "-" * 50)
            
            choice = input(f"{Fore.WHITE}Enter your choice (1-4): ").strip()
            
            if choice == '1':
                self.inventory_status()
            elif choice == '2':
                self.stock_movements()
            elif choice == '3':
                self.inventory_valuation()
            elif choice == '4':
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")
                input("Press Enter to continue...")
    
    def inventory_status(self):
        """Show inventory status"""
        inventory = self.inventory_manager.get_inventory_status()
        
        print(f"\n{Fore.GREEN}📊 INVENTORY STATUS")
        print(Fore.CYAN + "-" * 120)
        print(f"{'ID':<4} {'Name':<20} {'Batch':<12} {'Qty':<6} {'Price':<8} {'Cost':<8} {'Expiry':<12} {'Status':<12}")
        print(Fore.CYAN + "-" * 120)
        
        for item in inventory:
            status_color = Fore.GREEN
            if item['status'] == 'Low Stock':
                status_color = Fore.RED
            elif item['status'] == 'Near Expiry':
                status_color = Fore.YELLOW
            
            print(f"{item['medicine_id']:<4} {item['name']:<20} {item['batch_number']:<12} {item['quantity']:<6} ${item['price']:<7.2f} ${item['cost_price']:<7.2f} {item['expiry_date']:<12} {status_color}{item['status']:<12}{Style.RESET_ALL}")
        
        print(Fore.CYAN + "-" * 120)
        input("Press Enter to continue...")
    
    def reports_menu(self):
        """Reports and analytics menu"""
        while True:
            self.display_header()
            print(f"\n{Fore.GREEN}📊 REPORTS & ANALYTICS")
            print(Fore.CYAN + "-" * 50)
            print(f"{Fore.YELLOW}1. 📈 Sales Reports")
            print(f"{Fore.YELLOW}2. 📦 Inventory Reports")
            print(f"{Fore.YELLOW}3. 💰 Financial Summary")
            print(f"{Fore.YELLOW}4. ↩️  Back to Main Menu")
            print(Fore.CYAN + "-" * 50)
            
            choice = input(f"{Fore.WHITE}Enter your choice (1-4): ").strip()
            
            if choice == '1':
                self.sales_reports()
            elif choice == '2':
                self.inventory_reports()
            elif choice == '3':
                self.financial_summary()
            elif choice == '4':
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")
                input("Press Enter to continue...")
    
    def sales_reports(self):
        """Generate sales reports"""
        print(f"\n{Fore.GREEN}📈 SALES REPORTS")
        print(Fore.CYAN + "-" * 50)
        
        start_date = input("Start Date (YYYY-MM-DD): ")
        end_date = input("End Date (YYYY-MM-DD): ")
        
        print(f"\n1. Summary Report")
        print(f"2. Detailed Report")
        report_type = input("\nChoose report type (1-2): ")
        
        if report_type == '1':
            report = self.report_generator.generate_sales_report(start_date, end_date, 'summary')
        else:
            report = self.report_generator.generate_sales_report(start_date, end_date, 'detailed')
        
        print(f"\n{report}")
        input("Press Enter to continue...")
    
    def settings_menu(self):
        """Settings menu"""
        while True:
            self.display_header()
            print(f"\n{Fore.GREEN}⚙️  SETTINGS")
            print(Fore.CYAN + "-" * 50)
            print(f"{Fore.YELLOW}1. 🔐 Change Password")
            if self.auth.require_role('admin'):
                print(f"{Fore.YELLOW}2. 👥 User Management")
            print(f"{Fore.YELLOW}3. ↩️  Back to Main Menu")
            print(Fore.CYAN + "-" * 50)
            
            choice = input(f"{Fore.WHITE}Enter your choice (1-3): ").strip()
            
            if choice == '1':
                self.change_password()
            elif choice == '2' and self.auth.require_role('admin'):
                self.user_management()
            elif choice == '3':
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")
                input("Press Enter to continue...")
    
    def change_password(self):
        """Change user password"""
        print(f"\n{Fore.GREEN}🔐 CHANGE PASSWORD")
        print(Fore.CYAN + "-" * 50)
        
        old_password = input("Current Password: ")
        new_password = input("New Password: ")
        confirm_password = input("Confirm New Password: ")
        
        if new_password != confirm_password:
            print(f"{Fore.RED}New passwords don't match!")
            input("Press Enter to continue...")
            return
        
        success, message = self.auth.change_password(old_password, new_password)
        
        if success:
            print(f"\n{Fore.GREEN}✅ {message}")
        else:
            print(f"\n{Fore.RED}❌ {message}")
        
        input("Press Enter to continue...")
    
    def user_management(self):
        """User management (admin only)"""
        if not self.auth.require_role('admin'):
            print(f"{Fore.RED}Access denied!")
            return
        
        while True:
            self.display_header()
            print(f"\n{Fore.GREEN}👥 USER MANAGEMENT")
            print(Fore.CYAN + "-" * 50)
            print(f"{Fore.YELLOW}1. ➕ Create New User")
            print(f"{Fore.YELLOW}2. 📋 View All Users")
            print(f"{Fore.YELLOW}3. ↩️  Back to Settings")
            print(Fore.CYAN + "-" * 50)
            
            choice = input(f"{Fore.WHITE}Enter your choice (1-3): ").strip()
            
            if choice == '1':
                self.create_user()
            elif choice == '2':
                self.view_all_users()
            elif choice == '3':
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")
                input("Press Enter to continue...")
    
    def create_user(self):
        """Create a new user"""
        print(f"\n{Fore.GREEN}➕ CREATE NEW USER")
        print(Fore.CYAN + "-" * 50)
        
        username = input("Username: ")
        password = input("Password: ")
        full_name = input("Full Name: ")
        role = input("Role (admin/manager/staff): ")
        
        success, message = self.auth.create_user(username, password, full_name, role)
        
        if success:
            print(f"\n{Fore.GREEN}✅ {message}")
        else:
            print(f"\n{Fore.RED}❌ {message}")
        
        input("Press Enter to continue...")
    
    def view_all_users(self):
        """View all users"""
        users = self.auth.get_all_users()
        
        print(f"\n{Fore.GREEN}📋 ALL USERS")
        print(Fore.CYAN + "-" * 80)
        print(f"{'ID':<4} {'Username':<15} {'Full Name':<20} {'Role':<10} {'Last Login':<12}")
        print(Fore.CYAN + "-" * 80)
        
        for user in users:
            last_login = user['last_login'][:10] if user['last_login'] else 'Never'
            status = 'Active' if user['is_active'] else 'Inactive'
            print(f"{user['user_id']:<4} {user['username']:<15} {user['full_name']:<20} {user['role']:<10} {last_login:<12} {status}")
        
        print(Fore.CYAN + "-" * 80)
        input("Press Enter to continue...")
    
    def run(self):
        """Main program loop"""
        try:
            # Install bcrypt if not available
            try:
                import bcrypt
            except ImportError:
                print("Installing bcrypt...")
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install", "bcrypt"])
                import bcrypt
            
            # Login
            if not self.login_menu():
                return
            
            # Main application loop
            while True:
                self.display_header()
                self.display_main_menu()
                
                choice = input(f"{Fore.WHITE}Enter your choice (1-9): ").strip()
                
                if choice == '1':
                    self.medicine_management_menu()
                elif choice == '2':
                    self.sales_management_menu()
                elif choice == '3':
                    self.inventory_management_menu()
                elif choice == '4':
                    self.reports_menu()
                elif choice == '5' and self.auth.require_role(['admin', 'manager']):
                    self.customer_management_menu()
                elif choice == '6' and self.auth.require_role(['admin', 'manager']):
                    self.supplier_management_menu()
                elif choice == '7' and self.auth.require_role('admin'):
                    self.user_management()
                elif choice == '8':
                    self.settings_menu()
                elif choice == '9':
                    self.auth.logout()
                    print(f"{Fore.GREEN}✅ Logged out successfully!")
                    break
                else:
                    print(f"{Fore.RED}Invalid choice. Please try again.")
                    input("Press Enter to continue...")
                    
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}Program interrupted. Goodbye! 👋")
        except Exception as e:
            print(f"\n{Fore.RED}Unexpected error: {e}")

# Add missing menu methods
def customer_management_menu(self):
    """Customer management menu"""
    # Implementation similar to other menus
    pass

def supplier_management_menu(self):
    """Supplier management menu"""
    # Implementation similar to other menus
    pass

def search_medicines(self):
    """Search medicines"""
    # Implementation
    pass

def update_medicine(self):
    """Update medicine"""
    # Implementation
    pass

def expiry_alert(self):
    """Show expiry alert"""
    # Implementation
    pass

def view_sales_history(self):
    """View sales history"""
    # Implementation
    pass

def daily_sales_summary(self):
    """Show daily sales summary"""
    # Implementation
    pass

def stock_movements(self):
    """Show stock movements"""
    # Implementation
    pass

def inventory_valuation(self):
    """Show inventory valuation"""
    # Implementation
    pass

def inventory_reports(self):
    """Generate inventory reports"""
    # Implementation
    pass

def financial_summary(self):
    """Show financial summary"""
    # Implementation
    pass

# Add the methods to the class
MedicalStoreManagementSystem.customer_management_menu = customer_management_menu
MedicalStoreManagementSystem.supplier_management_menu = supplier_management_menu
MedicalStoreManagementSystem.search_medicines = search_medicines
MedicalStoreManagementSystem.update_medicine = update_medicine
MedicalStoreManagementSystem.expiry_alert = expiry_alert
MedicalStoreManagementSystem.view_sales_history = view_sales_history
MedicalStoreManagementSystem.daily_sales_summary = daily_sales_summary
MedicalStoreManagementSystem.stock_movements = stock_movements
MedicalStoreManagementSystem.inventory_valuation = inventory_valuation
MedicalStoreManagementSystem.inventory_reports = inventory_reports
MedicalStoreManagementSystem.financial_summary = financial_summary

if __name__ == "__main__":
    system = MedicalStoreManagementSystem()
    system.run()
import json
import os
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox
from currency_converter import CurrencyConverter
from prediction_engine import PredictionEngine
from auth_manager import AuthManager

class ExpenseTracker:
    def __init__(self, root):
        self.root = root
        self.root.title("Expense Note Tracker with User Management")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f5f6fa')
        
        # Initialize components
        self.auth_manager = AuthManager()
        self.currency_converter = CurrencyConverter()
        self.prediction_engine = PredictionEngine(self.currency_converter)
        
        # Data storage
        self.expenses = []
        self.categories = [
            "Food", "Transport", "Entertainment", "Shopping", 
            "Bills", "Healthcare", "Education", "Business", "Other"
        ]
        
        self.occupations = ["Student", "Working Professional", "Freelancer", "Family"]
        
        # Show login screen first
        self.show_login_screen()
    
    def show_login_screen(self):
        """Show login/registration screen"""
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="30")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Expense Note Tracker", 
                               font=('Arial', 20, 'bold'))
        title_label.pack(pady=(0, 30))
        
        # Notebook for Login/Register
        self.auth_notebook = ttk.Notebook(main_frame)
        self.auth_notebook.pack(fill='both', expand=True, padx=20)
        
        # Login Tab
        login_frame = ttk.Frame(self.auth_notebook, padding="20")
        self.auth_notebook.add(login_frame, text="Login")
        
        # Register Tab
        register_frame = ttk.Frame(self.auth_notebook, padding="20")
        self.auth_notebook.add(register_frame, text="Register")
        
        # Login Form
        ttk.Label(login_frame, text="Username:", font=('Arial', 10)).pack(anchor='w', pady=(10, 5))
        self.login_username = ttk.Entry(login_frame, width=30, font=('Arial', 10))
        self.login_username.pack(fill='x', pady=(0, 15))
        
        ttk.Label(login_frame, text="Password:", font=('Arial', 10)).pack(anchor='w', pady=(5, 5))
        self.login_password = ttk.Entry(login_frame, width=30, show='*', font=('Arial', 10))
        self.login_password.pack(fill='x', pady=(0, 20))
        
        ttk.Button(login_frame, text="Login", command=self.login).pack(pady=10)
        
        # Register Form
        ttk.Label(register_frame, text="Username:", font=('Arial', 10)).pack(anchor='w', pady=(10, 5))
        self.reg_username = ttk.Entry(register_frame, width=30, font=('Arial', 10))
        self.reg_username.pack(fill='x', pady=(0, 10))
        
        ttk.Label(register_frame, text="Email:", font=('Arial', 10)).pack(anchor='w', pady=(5, 5))
        self.reg_email = ttk.Entry(register_frame, width=30, font=('Arial', 10))
        self.reg_email.pack(fill='x', pady=(0, 10))
        
        ttk.Label(register_frame, text="Password:", font=('Arial', 10)).pack(anchor='w', pady=(5, 5))
        self.reg_password = ttk.Entry(register_frame, width=30, show='*', font=('Arial', 10))
        self.reg_password.pack(fill='x', pady=(0, 10))
        
        ttk.Label(register_frame, text="Occupation:", font=('Arial', 10)).pack(anchor='w', pady=(5, 5))
        self.reg_occupation = ttk.Combobox(register_frame, values=self.occupations, 
                                          state="readonly", font=('Arial', 10))
        self.reg_occupation.set("Student")
        self.reg_occupation.pack(fill='x', pady=(0, 10))
        
        ttk.Label(register_frame, text="Base Currency:", font=('Arial', 10)).pack(anchor='w', pady=(5, 5))
        self.reg_currency = ttk.Combobox(register_frame, 
                                        values=self.currency_converter.get_all_currencies(),
                                        state="readonly", font=('Arial', 10))
        self.reg_currency.set("USD")
        self.reg_currency.pack(fill='x', pady=(0, 20))
        
        ttk.Button(register_frame, text="Register", command=self.register).pack(pady=10)
        
        # Bind Enter key to login/register
        self.login_password.bind('<Return>', lambda e: self.login())
        self.reg_password.bind('<Return>', lambda e: self.register())
        
        # Focus on username field
        self.login_username.focus()
    
    def login(self):
        """Handle user login"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        success, message = self.auth_manager.login_user(username, password)
        
        if success:
            messagebox.showinfo("Success", message)
            self.load_user_data()
            self.create_main_interface()
        else:
            messagebox.showerror("Error", message)
    
    def register(self):
        """Handle user registration"""
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        password = self.reg_password.get()
        occupation = self.reg_occupation.get()
        base_currency = self.reg_currency.get()
        
        if not all([username, email, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        success, message = self.auth_manager.register_user(
            username, email, password, occupation, base_currency
        )
        
        if success:
            messagebox.showinfo("Success", message)
            # Switch to login tab and pre-fill username
            self.auth_notebook.select(0)
            self.login_username.delete(0, tk.END)
            self.login_username.insert(0, username)
            self.login_password.focus()
        else:
            messagebox.showerror("Error", message)
    
    def load_user_data(self):
        """Load current user's data"""
        self.expenses = self.auth_manager.load_user_expenses(self.auth_manager.current_user)
        user_data = self.auth_manager.get_current_user_data()
        
        if user_data:
            self.user_profile = {
                "occupation": user_data.get('occupation', 'Student'),
                "base_currency": user_data.get('base_currency', 'USD'),
                "monthly_budget": user_data.get('monthly_budget', 0)
            }
    
    def save_user_data(self):
        """Save current user's data"""
        self.auth_manager.save_user_expenses(self.auth_manager.current_user, self.expenses)
        self.auth_manager.update_user_profile(
            self.user_profile["occupation"],
            self.user_profile["base_currency"],
            self.user_profile["monthly_budget"]
        )
    
    def create_main_interface(self):
        """Create main application interface after login"""
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Create main menu bar
        self.create_menu_bar()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.setup_tab = ttk.Frame(self.notebook)
        self.expense_tab = ttk.Frame(self.notebook)
        self.prediction_tab = ttk.Frame(self.notebook)
        self.analysis_tab = ttk.Frame(self.notebook)
        self.admin_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.setup_tab, text="User Setup")
        self.notebook.add(self.expense_tab, text="Add Expenses")
        self.notebook.add(self.prediction_tab, text="Predictions")
        self.notebook.add(self.analysis_tab, text="Analysis")
        self.notebook.add(self.admin_tab, text="Admin")
        
        self.create_setup_tab()
        self.create_expense_tab()
        self.create_prediction_tab()
        self.create_analysis_tab()
        self.create_admin_tab()
        
        # Update all displays
        self.update_expenses_list()
        self.update_analysis()
    
    def create_menu_bar(self):
        """Create menu bar with user options"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # User menu
        user_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label=f"User: {self.auth_manager.current_user}", menu=user_menu)
        
        user_menu.add_command(label="My Profile", command=self.show_user_profile)
        user_menu.add_separator()
        user_menu.add_command(label="Logout", command=self.logout)
        user_menu.add_command(label="Exit", command=self.root.quit)
    
    def show_user_profile(self):
        """Show current user's profile information"""
        user_data = self.auth_manager.get_current_user_data()
        if not user_data:
            return
        
        profile_window = tk.Toplevel(self.root)
        profile_window.title("My Profile")
        profile_window.geometry("400x300")
        profile_window.transient(self.root)
        profile_window.grab_set()
        
        main_frame = ttk.Frame(profile_window, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        ttk.Label(main_frame, text="User Profile", font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # Profile information
        info_text = f"""
        Username: {self.auth_manager.current_user}
        Email: {user_data['email']}
        Occupation: {user_data.get('occupation', 'Not set')}
        Base Currency: {user_data.get('base_currency', 'USD')}
        Monthly Budget: {user_data.get('monthly_budget', 0):.2f}
        
        Account Created: {datetime.fromisoformat(user_data['created_at']).strftime('%Y-%m-%d %H:%M')}
        Last Login: {datetime.fromisoformat(user_data['last_login']).strftime('%Y-%m-%d %H:%M')}
        
        Total Expenses: {len(self.expenses)}
        """
        
        ttk.Label(main_frame, text=info_text, justify='left', font=('Arial', 10)).pack(anchor='w')
        
        ttk.Button(main_frame, text="Close", command=profile_window.destroy).pack(pady=20)
    
    def logout(self):
        """Logout current user"""
        self.save_user_data()
        self.auth_manager.logout_user()
        self.show_login_screen()
    
    def create_admin_tab(self):
        """Create admin tab for user management"""
        main_frame = ttk.Frame(self.admin_tab)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="User Statistics", font=('Arial', 14, 'bold')).pack(pady=(0, 10))
        
        # Refresh button
        ttk.Button(main_frame, text="Refresh Statistics", 
                  command=self.update_admin_tab).pack(pady=(0, 10))
        
        # Statistics text area
        self.admin_text = tk.Text(main_frame, height=20, width=80, font=('Arial', 9))
        self.admin_text.pack(fill='both', expand=True)
        
        self.update_admin_tab()
    
    def update_admin_tab(self):
        """Update admin tab with current statistics"""
        stats = self.auth_manager.get_all_users_stats()
        
        self.admin_text.delete(1.0, tk.END)
        
        summary = f"""
        SYSTEM STATISTICS
        =================
        Total Users: {stats['total_users']}
        
        """
        
        self.admin_text.insert(tk.END, summary)
        
        for username, user_stats in stats['users'].items():
            user_info = f"""
        USER: {username}
        Email: {user_stats['email']}
        Occupation: {user_stats['occupation']}
        Total Expenses: {user_stats['expense_count']}
        Total Amount: {user_stats['total_expenses']:.2f}
        Account Created: {datetime.fromisoformat(user_stats['created_at']).strftime('%Y-%m-%d')}
        Last Login: {datetime.fromisoformat(user_stats['last_login']).strftime('%Y-%m-%d %H:%M')}
        {'='*50}
            """
            self.admin_text.insert(tk.END, user_info)
    
    def create_setup_tab(self):
        """Create user setup tab"""
        setup_frame = ttk.LabelFrame(self.setup_tab, text="User Profile Setup", padding="15")
        setup_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Occupation
        ttk.Label(setup_frame, text="Occupation:").grid(row=0, column=0, sticky='w', pady=5)
        self.occupation_var = tk.StringVar(value=self.user_profile["occupation"])
        occupation_combo = ttk.Combobox(setup_frame, textvariable=self.occupation_var, 
                                       values=self.occupations, state="readonly", width=20)
        occupation_combo.grid(row=0, column=1, sticky='w', pady=5, padx=(10, 0))
        
        # Base Currency
        ttk.Label(setup_frame, text="Base Currency:").grid(row=1, column=0, sticky='w', pady=5)
        self.base_currency_var = tk.StringVar(value=self.user_profile["base_currency"])
        currency_combo = ttk.Combobox(setup_frame, textvariable=self.base_currency_var,
                                     values=self.currency_converter.get_all_currencies(), 
                                     state="readonly", width=20)
        currency_combo.grid(row=1, column=1, sticky='w', pady=5, padx=(10, 0))
        
        # Monthly Budget
        ttk.Label(setup_frame, text="Monthly Budget:").grid(row=2, column=0, sticky='w', pady=5)
        self.budget_var = tk.StringVar(value=str(self.user_profile["monthly_budget"]))
        budget_entry = ttk.Entry(setup_frame, textvariable=self.budget_var, width=23)
        budget_entry.grid(row=2, column=1, sticky='w', pady=5, padx=(10, 0))
        
        # Save Button
        ttk.Button(setup_frame, text="Save Profile", 
                  command=self.save_user_profile).grid(row=3, column=0, columnspan=2, pady=15)
        
        # Current user info
        user_data = self.auth_manager.get_current_user_data()
        if user_data:
            info_text = f"""
        Current User: {self.auth_manager.current_user}
        Email: {user_data['email']}
        
        Please set up your profile for accurate predictions:
        
        • Occupation: Helps determine spending patterns
        • Base Currency: Your primary currency for calculations
        • Monthly Budget: Your target monthly spending limit
        
        The system will use this information along with your 
        expense history to predict future monthly expenses.
        """
            info_label = ttk.Label(setup_frame, text=info_text, justify='left')
            info_label.grid(row=4, column=0, columnspan=2, sticky='w', pady=10)
    
    def save_user_profile(self):
        """Save user profile"""
        try:
            self.user_profile = {
                "occupation": self.occupation_var.get(),
                "base_currency": self.base_currency_var.get(),
                "monthly_budget": float(self.budget_var.get()) if self.budget_var.get() else 0
            }
            self.save_user_data()
            messagebox.showinfo("Success", "User profile saved successfully!")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid budget amount")
    
    def create_expense_tab(self):
        """Create expense management tab"""
        # Main frame
        main_frame = ttk.Frame(self.expense_tab)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Add New Expense", padding="10")
        input_frame.pack(fill='x', pady=(0, 10))
        
        # Amount
        ttk.Label(input_frame, text="Amount:").grid(row=0, column=0, sticky='w', pady=5)
        self.amount_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.amount_var, width=15).grid(row=0, column=1, sticky='w', pady=5, padx=(5, 15))
        
        # Currency
        ttk.Label(input_frame, text="Currency:").grid(row=0, column=2, sticky='w', pady=5)
        self.expense_currency_var = tk.StringVar(value=self.user_profile["base_currency"])
        ttk.Combobox(input_frame, textvariable=self.expense_currency_var,
                    values=self.currency_converter.get_all_currencies(), 
                    state="readonly", width=10).grid(row=0, column=3, sticky='w', pady=5, padx=(5, 15))
        
        # Category
        ttk.Label(input_frame, text="Category:").grid(row=1, column=0, sticky='w', pady=5)
        self.category_var = tk.StringVar()
        ttk.Combobox(input_frame, textvariable=self.category_var, values=self.categories, 
                    state="readonly", width=15).grid(row=1, column=1, sticky='w', pady=5, padx=(5, 15))
        
        # Description
        ttk.Label(input_frame, text="Description:").grid(row=1, column=2, sticky='w', pady=5)
        self.desc_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.desc_var, width=20).grid(row=1, column=3, sticky='w', pady=5, padx=(5, 15))
        
        # Date
        ttk.Label(input_frame, text="Date (YYYY-MM-DD):").grid(row=2, column=0, sticky='w', pady=5)
        self.date_var = tk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
        ttk.Entry(input_frame, textvariable=self.date_var, width=15).grid(row=2, column=1, sticky='w', pady=5, padx=(5, 15))
        
        # Add button
        ttk.Button(input_frame, text="Add Expense", command=self.add_expense).grid(row=2, column=2, columnspan=2, pady=5)
        
        # Expenses list
        list_frame = ttk.LabelFrame(main_frame, text="Recent Expenses", padding="10")
        list_frame.pack(fill='both', expand=True)
        
        # Treeview
        columns = ('Date', 'Amount', 'Currency', 'Category', 'Description', 'Amount in Base')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        
        self.tree.column('Description', width=150)
        self.tree.column('Amount in Base', width=120)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Bind double click to delete
        self.tree.bind('<Double-1>', self.delete_expense)
    
    def add_expense(self):
        """Add new expense"""
        try:
            amount = float(self.amount_var.get())
            currency = self.expense_currency_var.get()
            category = self.category_var.get()
            description = self.desc_var.get()
            date = self.date_var.get()
            
            if not category:
                messagebox.showerror("Error", "Please select a category")
                return
            
            # Validate date
            try:
                datetime.strptime(date, '%Y-%m-%d')
            except ValueError:
                messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD")
                return
            
            expense = {
                'date': date,
                'amount': amount,
                'currency': currency,
                'category': category,
                'description': description if description else "No description",
                'added_by': self.auth_manager.current_user,
                'added_at': datetime.now().isoformat()
            }
            
            self.expenses.append(expense)
            self.update_expenses_list()
            self.clear_inputs()
            self.save_user_data()
            self.update_analysis()
            messagebox.showinfo("Success", "Expense added successfully!")
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid amount")
    
    def delete_expense(self, event):
        """Delete selected expense"""
        selected = self.tree.selection()
        if selected:
            result = messagebox.askyesno("Confirm", "Delete this expense?")
            if result:
                index = self.tree.index(selected[0])
                if 0 <= index < len(self.expenses):
                    del self.expenses[index]
                    self.update_expenses_list()
                    self.save_user_data()
                    self.update_analysis()
    
    def clear_inputs(self):
        """Clear input fields"""
        self.amount_var.set("")
        self.desc_var.set("")
        self.date_var.set(datetime.now().strftime('%Y-%m-%d'))
        self.category_var.set("")
    
    def update_expenses_list(self):
        """Update the expenses list display"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add expenses (newest first)
        sorted_expenses = sorted(self.expenses, key=lambda x: x['date'], reverse=True)
        for expense in sorted_expenses:
            # Convert to base currency for display
            amount_in_base = self.currency_converter.convert(
                expense['amount'], 
                expense['currency'], 
                self.user_profile["base_currency"]
            )
            
            self.tree.insert('', 'end', values=(
                expense['date'],
                f"{expense['amount']:.2f}",
                expense['currency'],
                expense['category'],
                expense['description'],
                f"{amount_in_base:.2f} {self.user_profile['base_currency']}"
            ))
    
    def create_prediction_tab(self):
        """Create prediction tab"""
        main_frame = ttk.Frame(self.prediction_tab)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Prediction controls
        control_frame = ttk.LabelFrame(main_frame, text="Prediction Settings", padding="10")
        control_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(control_frame, text="Predict in Currency:").grid(row=0, column=0, sticky='w', pady=5)
        self.prediction_currency_var = tk.StringVar(value=self.user_profile["base_currency"])
        ttk.Combobox(control_frame, textvariable=self.prediction_currency_var,
                    values=self.currency_converter.get_all_currencies(), 
                    state="readonly", width=15).grid(row=0, column=1, sticky='w', pady=5, padx=(5, 15))
        
        ttk.Button(control_frame, text="Generate Prediction", 
                  command=self.generate_prediction).grid(row=0, column=2, pady=5, padx=(20, 0))
        
        # Prediction results
        self.prediction_frame = ttk.LabelFrame(main_frame, text="Monthly Expense Prediction", padding="15")
        self.prediction_frame.pack(fill='both', expand=True)
    
    def generate_prediction(self):
        """Generate expense prediction"""
        if not self.expenses:
            messagebox.showwarning("Warning", "No expense data available for prediction")
            return
        
        target_currency = self.prediction_currency_var.get()
        prediction = self.prediction_engine.predict_monthly_expense(
            self.expenses, 
            self.user_profile["occupation"],
            self.user_profile["base_currency"],
            target_currency
        )
        
        # Clear previous prediction
        for widget in self.prediction_frame.winfo_children():
            widget.destroy()
        
        # Display prediction
        symbol = self.currency_converter.get_currency_symbol(target_currency)
        
        # Total prediction
        total_frame = ttk.Frame(self.prediction_frame)
        total_frame.pack(fill='x', pady=5)
        
        ttk.Label(total_frame, text=f"Predicted Monthly Expense: ", 
                 font=('Arial', 12, 'bold')).pack(side='left')
        ttk.Label(total_frame, text=f"{symbol}{prediction['total']:,.2f} {target_currency}", 
                 font=('Arial', 12, 'bold'), foreground='#e74c3c').pack(side='left')
        
        # Confidence level
        confidence_color = '#27ae60' if prediction['confidence'] == 'high' else \
                          '#f39c12' if prediction['confidence'] == 'medium' else '#e74c3c'
        
        ttk.Label(total_frame, text=f" (Confidence: {prediction['confidence'].title()})", 
                 font=('Arial', 10), foreground=confidence_color).pack(side='left')
        
        # Method
        ttk.Label(self.prediction_frame, text=f"Prediction Method: {prediction['method'].replace('_', ' ').title()}",
                 font=('Arial', 9), foreground='#7f8c8d').pack(anchor='w', pady=(0, 10))
        
        # Category breakdown
        breakdown_frame = ttk.LabelFrame(self.prediction_frame, text="Category Breakdown", padding="10")
        breakdown_frame.pack(fill='both', expand=True, pady=5)
        
        for category, amount in prediction['breakdown'].items():
            cat_frame = ttk.Frame(breakdown_frame)
            cat_frame.pack(fill='x', pady=2)
            
            ttk.Label(cat_frame, text=category, width=15, anchor='w').pack(side='left')
            ttk.Label(cat_frame, text=f"{symbol}{amount:,.2f}", 
                     font=('Arial', 9, 'bold')).pack(side='left')
            
            percentage = (amount / prediction['total']) * 100
            ttk.Label(cat_frame, text=f"({percentage:.1f}%)", 
                     foreground='#7f8c8d').pack(side='left')
        
        # Budget comparison
        if self.user_profile["monthly_budget"] > 0:
            budget_frame = ttk.Frame(self.prediction_frame)
            budget_frame.pack(fill='x', pady=10)
            
            budget_in_target = self.currency_converter.convert(
                self.user_profile["monthly_budget"],
                self.user_profile["base_currency"],
                target_currency
            )
            
            difference = prediction['total'] - budget_in_target
            
            ttk.Label(budget_frame, text=f"Your Budget: {symbol}{budget_in_target:,.2f}", 
                     font=('Arial', 10)).pack(anchor='w')
            
            if difference > 0:
                ttk.Label(budget_frame, text=f"Over Budget by: {symbol}{difference:,.2f}", 
                         font=('Arial', 10, 'bold'), foreground='#e74c3c').pack(anchor='w')
            else:
                ttk.Label(budget_frame, text=f"Under Budget by: {symbol}{abs(difference):,.2f}", 
                         font=('Arial', 10, 'bold'), foreground='#27ae60').pack(anchor='w')
    
    def create_analysis_tab(self):
        """Create analysis tab"""
        main_frame = ttk.Frame(self.analysis_tab)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Summary frame
        summary_frame = ttk.LabelFrame(main_frame, text="Financial Summary", padding="10")
        summary_frame.pack(fill='x', pady=(0, 10))
        
        self.summary_text = tk.Text(summary_frame, height=8, width=80)
        self.summary_text.pack(fill='both', expand=True)
        
        # Currency conversion frame
        convert_frame = ttk.LabelFrame(main_frame, text="Currency Converter", padding="10")
        convert_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(convert_frame, text="Amount:").grid(row=0, column=0, sticky='w', pady=5)
        self.convert_amount_var = tk.StringVar()
        ttk.Entry(convert_frame, textvariable=self.convert_amount_var, width=15).grid(row=0, column=1, sticky='w', pady=5, padx=(5, 15))
        
        ttk.Label(convert_frame, text="From:").grid(row=0, column=2, sticky='w', pady=5)
        self.convert_from_var = tk.StringVar(value=self.user_profile["base_currency"])
        ttk.Combobox(convert_frame, textvariable=self.convert_from_var,
                    values=self.currency_converter.get_all_currencies(), 
                    state="readonly", width=10).grid(row=0, column=3, sticky='w', pady=5, padx=(5, 15))
        
        ttk.Label(convert_frame, text="To:").grid(row=0, column=4, sticky='w', pady=5)
        self.convert_to_var = tk.StringVar(value="EUR")
        ttk.Combobox(convert_frame, textvariable=self.convert_to_var,
                    values=self.currency_converter.get_all_currencies(), 
                    state="readonly", width=10).grid(row=0, column=5, sticky='w', pady=5, padx=(5, 15))
        
        ttk.Button(convert_frame, text="Convert", 
                  command=self.convert_currency).grid(row=0, column=6, pady=5, padx=(10, 0))
        
        self.convert_result_var = tk.StringVar()
        ttk.Label(convert_frame, textvariable=self.convert_result_var, 
                 font=('Arial', 10, 'bold')).grid(row=1, column=0, columnspan=7, pady=10)
    
    def convert_currency(self):
        """Convert currency"""
        try:
            amount = float(self.convert_amount_var.get())
            from_currency = self.convert_from_var.get()
            to_currency = self.convert_to_var.get()
            
            converted = self.currency_converter.convert(amount, from_currency, to_currency)
            from_symbol = self.currency_converter.get_currency_symbol(from_currency)
            to_symbol = self.currency_converter.get_currency_symbol(to_currency)
            
            self.convert_result_var.set(
                f"{from_symbol}{amount:,.2f} {from_currency} = {to_symbol}{converted:,.2f} {to_currency}"
            )
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid amount")
    
    def update_analysis(self):
        """Update analysis tab"""
        self.summary_text.delete(1.0, tk.END)
        
        if not self.expenses:
            self.summary_text.insert(tk.END, "No expense data available.")
            return
        
        # Calculate totals
        total_base = sum(
            self.currency_converter.convert(exp['amount'], exp['currency'], self.user_profile["base_currency"])
            for exp in self.expenses
        )
        
        # Current month total
        current_month = datetime.now().strftime('%Y-%m')
        month_expenses = [exp for exp in self.expenses if exp['date'].startswith(current_month)]
        month_total = sum(
            self.currency_converter.convert(exp['amount'], exp['currency'], self.user_profile["base_currency"])
            for exp in month_expenses
        )
        
        # Category breakdown
        category_totals = {}
        for exp in self.expenses:
            amount_base = self.currency_converter.convert(exp['amount'], exp['currency'], self.user_profile["base_currency"])
            category_totals[exp['category']] = category_totals.get(exp['category'], 0) + amount_base
        
        symbol = self.currency_converter.get_currency_symbol(self.user_profile["base_currency"])
        
        summary = f"""
Financial Summary:

Total Expenses: {symbol}{total_base:,.2f} {self.user_profile['base_currency']}
Current Month ({current_month}): {symbol}{month_total:,.2f} {self.user_profile['base_currency']}
Number of Transactions: {len(self.expenses)}

Category Breakdown:
"""
        for category, amount in sorted(category_totals.items(), key=lambda x: x[1], reverse=True):
            percentage = (amount / total_base) * 100
            summary += f"  {category}: {symbol}{amount:,.2f} ({percentage:.1f}%)\n"
        
        if self.user_profile["monthly_budget"] > 0:
            budget_usage = (month_total / self.user_profile["monthly_budget"]) * 100
            summary += f"\nBudget Usage: {budget_usage:.1f}% of monthly budget"
        
        self.summary_text.insert(tk.END, summary)
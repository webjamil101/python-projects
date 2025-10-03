import tkinter as tk
from tkinter import ttk, messagebox
from random import choice, randint, shuffle
import pyperclip
import json
import os
from datetime import datetime
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
import sqlite3
from typing import Optional, Tuple

class PasswordManager:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("MyPass - Secure Password Manager")
        self.window.geometry("1000x700")
        self.window.configure(bg='#1e1e1e')
        self.window.resizable(True, True)
        
        # Initialize security and database first
        self.setup_security()
        self.setup_database()
        
        # Configure styles
        self.setup_styles()
        
        # Create UI
        self.create_ui()
        
        # Load data
        self.load_passwords()

    def setup_security(self):
        """Initialize encryption and security components"""
        try:
            # Generate or load encryption key
            if not os.path.exists("master.key"):
                key = Fernet.generate_key()
                with open("master.key", "wb") as key_file:
                    key_file.write(key)
            
            with open("master.key", "rb") as key_file:
                key = key_file.read()
            
            self.cipher_suite = Fernet(key)
        except Exception as e:
            messagebox.showerror("Security Error", f"Failed to initialize security: {str(e)}")
            raise

    def setup_database(self):
        """Initialize SQLite database with proper error handling"""
        try:
            self.conn = sqlite3.connect('passwords.db', check_same_thread=False)
            self.cursor = self.conn.cursor()
            
            # Create table if it doesn't exist
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website TEXT NOT NULL,
                    email TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    date_added TEXT NOT NULL,
                    category TEXT DEFAULT 'General'
                )
            ''')
            
            self.conn.commit()
            print("Database initialized successfully")
            
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}")
            raise

    def setup_styles(self):
        """Configure modern ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Color scheme
        self.colors = {
            'bg': '#1e1e1e',
            'card_bg': '#2d2d2d',
            'accent': '#007acc',
            'success': '#4CAF50',
            'warning': '#FF9800',
            'danger': '#f44336',
            'text': '#ffffff',
            'text_secondary': '#cccccc'
        }
        
        # Configure styles
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['text'])
        style.configure('TButton', background=self.colors['accent'], foreground=self.colors['text'])
        style.configure('Accent.TButton', background=self.colors['accent'], foreground=self.colors['text'])
        style.configure('Success.TButton', background=self.colors['success'], foreground=self.colors['text'])
        style.configure('Danger.TButton', background=self.colors['danger'], foreground=self.colors['text'])
        style.configure('TEntry', fieldbackground=self.colors['card_bg'], foreground=self.colors['text'])
        style.configure('TLabelFrame', background=self.colors['bg'], foreground=self.colors['text'])
        style.configure('TLabelframe.Label', background=self.colors['bg'], foreground=self.colors['text'])
        style.configure('Treeview', 
                       background=self.colors['card_bg'],
                       foreground=self.colors['text'],
                       fieldbackground=self.colors['card_bg'])
        style.configure('Treeview.Heading', 
                       background=self.colors['accent'],
                       foreground=self.colors['text'])

    def create_ui(self):
        """Create the user interface"""
        # Main container
        main_container = ttk.Frame(self.window)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        self.create_header(main_container)
        
        # Main content area
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=20)
        
        # Left panel - Input form
        left_panel = ttk.LabelFrame(content_frame, text="Add New Password", padding=15)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.create_input_form(left_panel)
        
        # Right panel - Password list
        right_panel = ttk.LabelFrame(content_frame, text="Saved Passwords", padding=15)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        self.create_password_list(right_panel)
        
        # Status bar
        self.create_status_bar(main_container)

    def create_header(self, parent):
        """Create application header"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            header_frame,
            text="MyPass",
            font=("Segoe UI", 24, "bold"),
            bg=self.colors['bg'],
            fg=self.colors['accent']
        )
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = tk.Label(
            header_frame,
            text="Secure Password Manager",
            font=("Segoe UI", 12),
            bg=self.colors['bg'],
            fg=self.colors['text_secondary']
        )
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0), pady=8)
        
        # Security indicator
        security_frame = ttk.Frame(header_frame)
        security_frame.pack(side=tk.RIGHT)
        
        security_indicator = tk.Label(
            security_frame,
            text="🔒 Encrypted",
            font=("Segoe UI", 10),
            bg=self.colors['success'],
            fg="white",
            padx=10,
            pady=5,
            bd=0,
            relief="flat"
        )
        security_indicator.pack()

    def create_input_form(self, parent):
        """Create password input form"""
        # Website
        website_frame = ttk.Frame(parent)
        website_frame.pack(fill=tk.X, pady=8)
        
        ttk.Label(website_frame, text="Website:").pack(side=tk.LEFT, padx=(0, 10))
        self.website_entry = ttk.Entry(website_frame, width=30)
        self.website_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.website_entry.focus()
        
        # Category
        category_frame = ttk.Frame(parent)
        category_frame.pack(fill=tk.X, pady=8)
        
        ttk.Label(category_frame, text="Category:").pack(side=tk.LEFT, padx=(0, 10))
        self.category_var = tk.StringVar(value="General")
        category_combo = ttk.Combobox(
            category_frame, 
            textvariable=self.category_var,
            values=["General", "Social Media", "Email", "Banking", "Work", "Personal"],
            state="readonly",
            width=28
        )
        category_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Email/Username
        email_frame = ttk.Frame(parent)
        email_frame.pack(fill=tk.X, pady=8)
        
        ttk.Label(email_frame, text="Email/Username:").pack(side=tk.LEFT, padx=(0, 10))
        self.email_entry = ttk.Entry(email_frame, width=30)
        self.email_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.email_entry.insert(0, "user@example.com")
        
        # Password
        password_frame = ttk.Frame(parent)
        password_frame.pack(fill=tk.X, pady=8)
        
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT, padx=(0, 10))
        self.password_entry = ttk.Entry(password_frame, width=30, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Password strength indicator
        self.strength_var = tk.StringVar(value="Strength: -")
        strength_label = ttk.Label(password_frame, textvariable=self.strength_var)
        strength_label.pack(side=tk.RIGHT, padx=(10, 0))
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Enhanced Generate password options
        gen_frame = ttk.Frame(parent)
        gen_frame.pack(fill=tk.X, pady=8)
        
        ttk.Label(gen_frame, text="Length:").pack(side=tk.LEFT, padx=(0, 10))
        self.length_var = tk.IntVar(value=16)
        length_spin = ttk.Spinbox(gen_frame, from_=8, to=50, textvariable=self.length_var, width=5)
        length_spin.pack(side=tk.LEFT)
        
        # Store checkbox variables as instance attributes
        self.use_symbols = tk.BooleanVar(value=True)
        self.use_numbers = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(gen_frame, text="Symbols", variable=self.use_symbols).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Checkbutton(gen_frame, text="Numbers", variable=self.use_numbers).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Checkbutton(gen_frame, text="Uppercase", variable=self.use_uppercase).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Checkbutton(gen_frame, text="Lowercase", variable=self.use_lowercase).pack(side=tk.LEFT, padx=(5, 0))
        
        # Custom Symbols Frame
        symbols_frame = ttk.LabelFrame(parent, text="Custom Symbols", padding=10)
        symbols_frame.pack(fill=tk.X, pady=8)
        
        # Default symbols
        self.default_symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        self.custom_symbols_var = tk.StringVar(value=self.default_symbols)
        
        symbols_label = ttk.Label(symbols_frame, text="Symbols to use:")
        symbols_label.pack(anchor=tk.W)
        
        symbols_entry_frame = ttk.Frame(symbols_frame)
        symbols_entry_frame.pack(fill=tk.X, pady=5)
        
        self.symbols_entry = ttk.Entry(symbols_entry_frame, textvariable=self.custom_symbols_var, width=40)
        self.symbols_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Reset to default symbols button
        ttk.Button(
            symbols_entry_frame, 
            text="Reset", 
            command=self.reset_symbols_to_default,
            width=8
        ).pack(side=tk.RIGHT, padx=(10, 0))
        
        # Numbers customization
        numbers_frame = ttk.LabelFrame(parent, text="Custom Numbers", padding=10)
        numbers_frame.pack(fill=tk.X, pady=8)
        
        self.custom_numbers_var = tk.StringVar(value='0123456789')
        
        numbers_label = ttk.Label(numbers_frame, text="Numbers to use:")
        numbers_label.pack(anchor=tk.W)
        
        numbers_entry_frame = ttk.Frame(numbers_frame)
        numbers_entry_frame.pack(fill=tk.X, pady=5)
        
        self.numbers_entry = ttk.Entry(numbers_entry_frame, textvariable=self.custom_numbers_var, width=40)
        self.numbers_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Reset to default numbers button
        ttk.Button(
            numbers_entry_frame, 
            text="Reset", 
            command=self.reset_numbers_to_default,
            width=8
        ).pack(side=tk.RIGHT, padx=(10, 0))
        
        # Buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=20)
        
        ttk.Button(
            button_frame, 
            text="Generate Password", 
            command=self.generate_advanced_password,
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame, 
            text="Add Password", 
            command=self.save_password,
            style="Success.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame, 
            text="Search Website", 
            command=self.search_password,
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame, 
            text="Show All", 
            command=self.load_passwords
        ).pack(side=tk.RIGHT)

    def create_password_list(self, parent):
        """Create password list with advanced features"""
        # Search and filter
        search_frame = ttk.Frame(parent)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 10))
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind('<KeyRelease>', self.filter_passwords)
        
        # Clear filter button
        ttk.Button(
            search_frame,
            text="Clear Filter",
            command=self.clear_filter,
            width=12
        ).pack(side=tk.RIGHT, padx=(10, 0))
        
        # Password list
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Website", "Category", "Email", "Password", "Date Added")
        self.password_tree = ttk.Treeview(
            list_frame, 
            columns=columns, 
            show="headings",
            height=15
        )
        
        # Configure columns
        column_widths = {"Website": 150, "Category": 100, "Email": 180, "Password": 120, "Date Added": 120}
        for col in columns:
            self.password_tree.heading(col, text=col)
            self.password_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        h_scroll = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.password_tree.xview)
        self.password_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind events
        self.password_tree.bind('<Double-1>', self.copy_password)
        self.password_tree.bind('<<TreeviewSelect>>', self.on_password_select)
        
        # Action buttons
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            action_frame, 
            text="Copy Password", 
            command=self.copy_selected_password
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame, 
            text="Show Password", 
            command=self.show_selected_password
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame, 
            text="Auto-Fill Form", 
            command=self.auto_fill_from_selection
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame, 
            text="Delete", 
            command=self.delete_password,
            style="Danger.TButton"
        ).pack(side=tk.RIGHT)

    def create_status_bar(self, parent):
        """Create status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(
            status_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_label.pack(fill=tk.X)

    # Custom Symbols and Numbers Methods
    def reset_symbols_to_default(self):
        """Reset symbols to default set"""
        self.custom_symbols_var.set(self.default_symbols)
        self.update_status("Symbols reset to default")

    def reset_numbers_to_default(self):
        """Reset numbers to default set"""
        self.custom_numbers_var.set('0123456789')
        self.update_status("Numbers reset to default")

    def get_custom_symbols(self):
        """Get custom symbols from entry, fallback to default if empty"""
        custom_symbols = self.custom_symbols_var.get().strip()
        if not custom_symbols:
            return self.default_symbols
        return custom_symbols

    def get_custom_numbers(self):
        """Get custom numbers from entry, fallback to default if empty"""
        custom_numbers = self.custom_numbers_var.get().strip()
        if not custom_numbers:
            return '0123456789'
        return custom_numbers

    # Security Methods
    def hash_password(self, password: str) -> Tuple[str, str]:
        """Hash password with salt using PBKDF2"""
        salt = secrets.token_bytes(32)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # 100,000 iterations
        )
        return base64.b64encode(password_hash).decode('utf-8'), base64.b64encode(salt).decode('utf-8')

    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash"""
        salt_bytes = base64.b64decode(salt)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt_bytes,
            100000
        )
        return base64.b64encode(password_hash).decode('utf-8') == stored_hash

    def encrypt_data(self, data: str) -> str:
        """Encrypt data using Fernet symmetric encryption"""
        return self.cipher_suite.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data using Fernet symmetric encryption"""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    # Enhanced Password Generation with Custom Symbols and Numbers
    def generate_advanced_password(self):
        """Generate secure password with customizable options including custom symbols and numbers"""
        try:
            length = self.length_var.get()
            
            # Get character sets based on user selections
            lowercase = 'abcdefghijklmnopqrstuvwxyz' if self.use_lowercase.get() else ''
            uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if self.use_uppercase.get() else ''
            numbers = self.get_custom_numbers() if self.use_numbers.get() else ''
            symbols = self.get_custom_symbols() if self.use_symbols.get() else ''
            
            # Build character set based on options
            chars = lowercase + uppercase + numbers + symbols
            
            # Check if at least one character set is selected
            if not chars:
                messagebox.showwarning("Generation Error", "Please select at least one character type (Lowercase, Uppercase, Numbers, or Symbols)")
                return
            
            # Ensure password meets basic requirements
            password_parts = []
            
            if self.use_lowercase.get() and lowercase:
                password_parts.append(choice(lowercase))
            if self.use_uppercase.get() and uppercase:
                password_parts.append(choice(uppercase))
            if self.use_numbers.get() and numbers:
                password_parts.append(choice(numbers))
            if self.use_symbols.get() and symbols:
                password_parts.append(choice(symbols))
            
            # Fill remaining length
            remaining_length = max(0, length - len(password_parts))
            if remaining_length > 0:
                password_parts += [choice(chars) for _ in range(remaining_length)]
            
            # Shuffle to randomize order
            shuffle(password_parts)
            
            generated = ''.join(password_parts)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, generated)
            self.check_password_strength()
            pyperclip.copy(generated)
            self.update_status("Password generated and copied to clipboard!")
            
        except Exception as e:
            messagebox.showerror("Generation Error", f"Failed to generate password: {str(e)}")

    def check_password_strength(self, event=None):
        """Analyze password strength"""
        password = self.password_entry.get()
        if not password:
            self.strength_var.set("Strength: -")
            return
        
        score = 0
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if len(password) >= 16: score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password): score += 1
        
        strength_levels = {
            0: ("Very Weak", "#f44336"),
            1: ("Very Weak", "#f44336"),
            2: ("Weak", "#FF9800"),
            3: ("Fair", "#FFC107"),
            4: ("Good", "#8BC34A"),
            5: ("Strong", "#4CAF50"),
            6: ("Very Strong", "#2E7D32"),
            7: ("Excellent", "#1B5E20")
        }
        
        level, color = strength_levels.get(score, ("Unknown", "#757575"))
        self.strength_var.set(f"Strength: {level}")
        
        # Find and update the strength label to change color
        for widget in self.password_entry.master.winfo_children():
            if isinstance(widget, ttk.Label) and widget.cget('textvariable') == self.strength_var._name:
                widget.configure(foreground=color)
                break

    # Database Operations
    def save_password(self):
        """Save password to database with encryption"""
        website = self.website_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        category = self.category_var.get()

        if not all([website, email, password]):
            messagebox.showwarning("Error", "Please fill in all fields.")
            self.update_status("Error: Please fill all fields")
            return

        try:
            # Check if website already exists
            self.cursor.execute('SELECT website FROM passwords WHERE website = ?', (website,))
            existing = self.cursor.fetchone()
            
            encrypted_password = self.encrypt_data(password)
            password_hash, salt = self.hash_password(password)
            current_time = datetime.now().isoformat()
            
            if existing:
                response = messagebox.askyesno(
                    "Duplicate Website", 
                    f"A password for '{website}' already exists. Do you want to update it?"
                )
                if not response:
                    return
                # Update existing entry
                self.cursor.execute('''
                    UPDATE passwords 
                    SET email = ?, encrypted_password = ?, salt = ?, date_added = ?, category = ?
                    WHERE website = ?
                ''', (email, encrypted_password, salt, current_time, category, website))
                action = "updated"
            else:
                # Insert new entry
                self.cursor.execute('''
                    INSERT INTO passwords (website, email, encrypted_password, salt, date_added, category)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (website, email, encrypted_password, salt, current_time, category))
                action = "saved"
            
            self.conn.commit()
            
            # Clear form and update list
            self.website_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.load_passwords()
            
            self.update_status(f"Password for {website} {action} securely!")
            messagebox.showinfo("Success", f"Password for {website} {action} successfully!")
            
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to save password: {str(e)}")
            self.update_status("Error saving password")

    def load_passwords(self):
        """Load passwords from database"""
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        try:
            self.cursor.execute('SELECT website, category, email, encrypted_password, date_added FROM passwords ORDER BY website')
            for row in self.cursor.fetchall():
                website, category, email, encrypted_password, date_added = row
                
                # Decrypt password for display (masked)
                try:
                    decrypted_password = self.decrypt_data(encrypted_password)
                    masked_password = "•" * len(decrypted_password)
                except:
                    masked_password = "Error"
                
                # Format date
                try:
                    date_obj = datetime.fromisoformat(date_added)
                    formatted_date = date_obj.strftime("%Y-%m-%d")
                except:
                    formatted_date = "Unknown"
                
                self.password_tree.insert("", tk.END, values=(
                    website, category, email, masked_password, formatted_date
                ))
                
        except Exception as e:
            self.update_status(f"Error loading passwords: {str(e)}")

    def search_password(self):
        """Search for passwords by website name - FIXED VERSION"""
        website = self.website_entry.get().strip()
        if not website:
            messagebox.showwarning("Search", "Please enter a website name to search for.")
            return
        
        try:
            # Search for exact or partial matches
            self.cursor.execute(
                'SELECT website, category, email, encrypted_password, date_added FROM passwords WHERE website LIKE ?',
                (f'%{website}%',)
            )
            results = self.cursor.fetchall()
            
            if results:
                # Clear the treeview and show only search results
                for item in self.password_tree.get_children():
                    self.password_tree.delete(item)
                
                for result in results:
                    website, category, email, encrypted_password, date_added = result
                    
                    # Decrypt password for display (masked)
                    try:
                        decrypted_password = self.decrypt_data(encrypted_password)
                        masked_password = "•" * len(decrypted_password)
                    except:
                        masked_password = "Error"
                    
                    # Format date
                    try:
                        date_obj = datetime.fromisoformat(date_added)
                        formatted_date = date_obj.strftime("%Y-%m-%d")
                    except:
                        formatted_date = "Unknown"
                    
                    self.password_tree.insert("", tk.END, values=(
                        website, category, email, masked_password, formatted_date
                    ))
                
                self.update_status(f"Found {len(results)} password(s) for '{website}'")
                
                # Auto-fill form if exact match found
                exact_matches = [r for r in results if r[0].lower() == website.lower()]
                if exact_matches:
                    self.auto_fill_form(exact_matches[0])
                    self.update_status(f"Auto-filled form for exact match: {website}")
                    
            else:
                messagebox.showinfo("Not Found", f"No passwords found for '{website}'")
                self.update_status(f"No passwords found for '{website}'")
                
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {str(e)}")
            self.update_status("Search failed")

    def auto_fill_form(self, record):
        """Auto-fill form with selected record data"""
        website, category, email, encrypted_password, date_added = record
        
        # Decrypt password for display
        try:
            decrypted_password = self.decrypt_data(encrypted_password)
        except:
            decrypted_password = ""
        
        # Fill the form
        self.website_entry.delete(0, tk.END)
        self.website_entry.insert(0, website)
        
        self.email_entry.delete(0, tk.END)
        self.email_entry.insert(0, email)
        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, decrypted_password)
        
        self.category_var.set(category)
        
        self.update_status(f"Auto-filled form for {website}")

    def auto_fill_from_selection(self):
        """Auto-fill form from selected item in the list"""
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showwarning("Selection", "Please select a password entry to auto-fill.")
            return
        
        item = selected[0]
        website = self.password_tree.item(item)['values'][0]
        
        try:
            self.cursor.execute(
                'SELECT website, category, email, encrypted_password, date_added FROM passwords WHERE website = ?',
                (website,)
            )
            result = self.cursor.fetchone()
            
            if result:
                self.auto_fill_form(result)
            else:
                messagebox.showerror("Error", "Could not find the selected password entry.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to auto-fill: {str(e)}")

    def filter_passwords(self, event=None):
        """Filter passwords based on search term in the filter box"""
        search_term = self.search_entry.get().strip().lower()
        
        # Show all items if search is empty
        if not search_term:
            for item in self.password_tree.get_children():
                self.password_tree.item(item, tags=('visible',))
            return
        
        # Filter items based on search term
        for item in self.password_tree.get_children():
            values = self.password_tree.item(item)['values']
            website = values[0].lower() if values[0] else ""
            category = values[1].lower() if values[1] else ""
            email = values[2].lower() if values[2] else ""
            
            if (search_term in website or search_term in category or 
                search_term in email):
                self.password_tree.item(item, tags=('visible',))
            else:
                self.password_tree.item(item, tags=('hidden',))
        
        # Configure tag colors
        self.password_tree.tag_configure('visible', background=self.colors['card_bg'])
        self.password_tree.tag_configure('hidden', background='#3d3d3d')

    def clear_filter(self):
        """Clear the filter and show all passwords"""
        self.search_entry.delete(0, tk.END)
        self.load_passwords()
        self.update_status("Filter cleared")

    # Password Management methods
    def copy_selected_password(self):
        """Copy selected password to clipboard"""
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showwarning("Selection", "Please select a password to copy.")
            return
        
        item = selected[0]
        website = self.password_tree.item(item)['values'][0]
        
        try:
            self.cursor.execute(
                'SELECT encrypted_password FROM passwords WHERE website = ?',
                (website,)
            )
            result = self.cursor.fetchone()
            
            if result:
                encrypted_password = result[0]
                decrypted_password = self.decrypt_data(encrypted_password)
                pyperclip.copy(decrypted_password)
                self.update_status(f"Password for {website} copied to clipboard!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")

    def show_selected_password(self):
        """Show selected password temporarily"""
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showwarning("Selection", "Please select a password to view.")
            return
        
        item = selected[0]
        website = self.password_tree.item(item)['values'][0]
        
        try:
            self.cursor.execute(
                'SELECT encrypted_password FROM passwords WHERE website = ?',
                (website,)
            )
            result = self.cursor.fetchone()
            
            if result:
                encrypted_password = result[0]
                decrypted_password = self.decrypt_data(encrypted_password)
                self.show_password_popup(website, decrypted_password)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")

    def show_password_popup(self, website: str, password: str):
        """Show password in a temporary popup"""
        popup = tk.Toplevel(self.window)
        popup.title(f"Password for {website}")
        popup.geometry("300x150")
        popup.configure(bg=self.colors['bg'])
        popup.resizable(False, False)
        
        popup.transient(self.window)
        popup.grab_set()
        
        ttk.Label(popup, text=f"Password for {website}:", font=("Segoe UI", 10, "bold")).pack(pady=10)
        
        password_frame = ttk.Frame(popup)
        password_frame.pack(pady=10)
        
        password_entry = ttk.Entry(
            password_frame, 
            font=("Consolas", 12),
            width=20,
            justify='center'
        )
        password_entry.insert(0, password)
        password_entry.config(state='readonly')
        password_entry.pack()
        
        ttk.Button(
            popup, 
            text="Copy & Close", 
            command=lambda: [pyperclip.copy(password), popup.destroy()]
        ).pack(pady=10)
        
        popup.after(10000, popup.destroy)

    def copy_password(self, event=None):
        self.copy_selected_password()

    def on_password_select(self, event):
        """Handle password selection"""
        pass

    def delete_password(self):
        """Delete selected password"""
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showwarning("Selection", "Please select a password to delete.")
            return
        
        item = selected[0]
        website = self.password_tree.item(item)['values'][0]
        
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete the password for '{website}'?\nThis action cannot be undone."
        )
        
        if confirm:
            try:
                self.cursor.execute('DELETE FROM passwords WHERE website = ?', (website,))
                self.conn.commit()
                self.load_passwords()
                self.update_status(f"Password for {website} deleted.")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete password: {str(e)}")

    def update_status(self, message: str):
        """Update status bar"""
        self.status_var.set(message)
        self.window.after(5000, lambda: self.status_var.set("Ready"))

    def run(self):
        """Start the application"""
        self.window.mainloop()
        
    def __del__(self):
        """Cleanup when application closes"""
        if hasattr(self, 'conn'):
            self.conn.close()

# Run the application
if __name__ == "__main__":
    app = PasswordManager()
    app.run()
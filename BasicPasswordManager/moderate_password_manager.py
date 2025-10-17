from tkinter import *
from tkinter import messagebox, ttk
from random import choice, randint, shuffle
import pyperclip
import json
import os
import sys

# ---------------------------- PASSWORD GENERATOR ------------------------------- #

def generate_password():
    """
    Generate password(s) with variable length and enhanced error handling
    """
    try:
        # Validate length
        length_str = length_var.get().strip()
        if not length_str:
            messagebox.showwarning("Invalid Input", "Please enter a password length")
            return
            
        length = int(length_str)
        if length < 4:
            messagebox.showwarning("Invalid Length", "Password length must be at least 4 characters for security")
            return
        if length > 100:
            messagebox.showwarning("Invalid Length", "Password length cannot exceed 100 characters")
            return
            
    except ValueError:
        messagebox.showwarning("Invalid Length", "Please enter a valid number for password length (4-100)")
        return
    except Exception as e:
        messagebox.showerror("Unexpected Error", f"Error processing length: {str(e)}")
        return
    
    try:
        # Validate count
        count_str = count_var.get().strip()
        if not count_str:
            messagebox.showwarning("Invalid Input", "Please enter the number of passwords to generate")
            return
            
        count = int(count_str)
        if count < 1:
            messagebox.showwarning("Invalid Count", "Number of passwords must be at least 1")
            return
        if count > 50:  # Increased limit for flexibility
            messagebox.showwarning("Invalid Count", "Number of passwords cannot exceed 50")
            return
            
    except ValueError:
        messagebox.showwarning("Invalid Count", "Please enter a valid number for password count (1-50)")
        return
    except Exception as e:
        messagebox.showerror("Unexpected Error", f"Error processing count: {str(e)}")
        return

    try:
        # Character sets with more variety
        letters = [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
        ]
        
        numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        
        symbols = [
            '!', '#', '$', '%', '&', '(', ')', '*', '+', '-', '.', '/', ':', 
            ';', '<', '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', 
            '}', '~'
        ]
        
        # Advanced character sets for stronger passwords
        similar_chars = {'i', 'l', '1', 'o', '0', 'O'}  # Characters that look similar
        ambiguous_chars = {'{', '}', '(', ')', '[', ']', '/', '\\', '\'', '"', '`', '~', ',', '.', ';', ':'}
        
        # Filter out similar looking characters if requested
        if avoid_similar_var.get():
            letters = [char for char in letters if char not in similar_chars]
        
        # Filter out ambiguous characters if requested
        if avoid_ambiguous_var.get():
            symbols = [char for char in symbols if char not in ambiguous_chars]
        
        passwords = []
        
        for password_num in range(count):
            try:
                # Smart distribution based on length
                if length <= 8:
                    # Short passwords: balanced distribution
                    nr_letters = max(3, length // 2)
                    nr_symbols = max(1, length // 4)
                    nr_numbers = max(1, length - nr_letters - nr_symbols)
                elif length <= 16:
                    # Medium passwords: more letters
                    nr_letters = max(4, length * 3 // 4)
                    nr_symbols = max(1, length // 6)
                    nr_numbers = max(1, length - nr_letters - nr_symbols)
                else:
                    # Long passwords: emphasis on variety
                    nr_letters = max(6, length // 2)
                    nr_symbols = max(2, length // 5)
                    nr_numbers = max(2, length - nr_letters - nr_symbols)
                
                # Ensure we have at least one of each type for stronger passwords
                if nr_symbols == 0 and len(symbols) > 0:
                    nr_symbols = 1
                    nr_letters = max(1, nr_letters - 1)
                if nr_numbers == 0:
                    nr_numbers = 1
                    nr_letters = max(1, nr_letters - 1)
                
                # Adjust if total exceeds desired length
                total = nr_letters + nr_symbols + nr_numbers
                if total > length:
                    # Reduce letters first since we have more of them
                    nr_letters = max(1, nr_letters - (total - length))
                elif total < length:
                    # Add more letters to fill
                    nr_letters += (length - total)
                
                # Generate password components with error handling
                password_letters = []
                password_symbols = []
                password_numbers = []
                
                if nr_letters > 0 and letters:
                    password_letters = [choice(letters) for _ in range(nr_letters)]
                
                if nr_symbols > 0 and symbols:
                    password_symbols = [choice(symbols) for _ in range(nr_symbols)]
                
                if nr_numbers > 0 and numbers:
                    password_numbers = [choice(numbers) for _ in range(nr_numbers)]
                
                # Combine and shuffle
                password_list = password_letters + password_symbols + password_numbers
                
                if not password_list:
                    raise ValueError("No characters available to generate password")
                
                shuffle(password_list)
                password = "".join(password_list)
                passwords.append(password)
                
            except Exception as e:
                # Log individual password generation errors but continue
                print(f"Error generating password {password_num + 1}: {str(e)}")
                # Add a fallback simple password
                fallback_chars = letters + numbers + symbols
                if fallback_chars:
                    fallback_password = ''.join(choice(fallback_chars) for _ in range(max(8, length)))
                    passwords.append(fallback_password)
                else:
                    # Ultimate fallback
                    passwords.append(f"Password{password_num + 1}")
        
        if not passwords:
            raise ValueError("No passwords were generated")
        
        # Handle single vs multiple passwords
        if count == 1:
            password_entry.delete(0, END)
            password_entry.insert(0, passwords[0])
            try:
                pyperclip.copy(passwords[0])
                messagebox.showinfo("Password Generated", 
                                  "Password generated and copied to clipboard!\n"
                                  f"Length: {len(passwords[0])} characters")
            except Exception as e:
                messagebox.showinfo("Password Generated", 
                                  f"Password generated!\n"
                                  f"Length: {len(passwords[0])} characters\n"
                                  f"Note: Could not copy to clipboard: {str(e)}")
        else:
            show_password_selection(passwords)
            
    except Exception as e:
        messagebox.showerror("Generation Error", 
                           f"Failed to generate passwords:\n{str(e)}\n"
                           "Please try different settings.")
        print(f"Password generation error: {str(e)}")

def show_password_selection(passwords):
    """Show password selection dialog with enhanced error handling"""
    try:
        selection_window = Toplevel(window)
        selection_window.title("Select a Password")
        selection_window.geometry("500x400")
        selection_window.transient(window)
        selection_window.grab_set()
        selection_window.configure(bg='#ffffff')
        
        # Make window responsive
        selection_window.columnconfigure(0, weight=1)
        selection_window.rowconfigure(0, weight=1)
        
        frame = Frame(selection_window, padx=20, pady=20, bg='#ffffff')
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        
        Label(frame, text="Choose a Password", font=("Arial", 16, "bold"), 
              bg='#ffffff', fg='#333333').grid(row=0, column=0, sticky="w", pady=(0, 15))
        
        # Password stats
        stats_text = f"Generated {len(passwords)} passwords ({len(passwords[0])} chars each)"
        Label(frame, text=stats_text, font=("Arial", 10), 
              bg='#ffffff', fg='#666666').grid(row=1, column=0, sticky="w", pady=(0, 10))
        
        # Create listbox with scrollbar
        listbox_frame = Frame(frame, bg='#ffffff')
        listbox_frame.grid(row=2, column=0, sticky="nsew", pady=10)
        listbox_frame.columnconfigure(0, weight=1)
        listbox_frame.rowconfigure(0, weight=1)
        
        listbox = Listbox(listbox_frame, height=12, font=("Courier", 10), 
                         bg='#f8f9fa', fg='#333333', 
                         selectbackground='#007bff', selectforeground='white', 
                         relief='flat', bd=1)
        scrollbar = Scrollbar(listbox_frame, orient="vertical")
        
        listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=listbox.yview)
        
        listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Add passwords to listbox with strength indicator
        for i, password in enumerate(passwords, 1):
            strength = get_password_strength(password)
            strength_color = {
                "Weak": "red",
                "Medium": "orange", 
                "Strong": "green",
                "Very Strong": "darkgreen"
            }[strength]
            
            listbox.insert(END, f"{i:2d}. {password}")
        
        def select_password():
            try:
                selection = listbox.curselection()
                if selection:
                    selected_password = passwords[selection[0]]
                    password_entry.delete(0, END)
                    password_entry.insert(0, selected_password)
                    try:
                        pyperclip.copy(selected_password)
                        selection_window.destroy()
                        messagebox.showinfo("Password Selected", 
                                          "Password selected and copied to clipboard!")
                    except Exception as e:
                        selection_window.destroy()
                        messagebox.showinfo("Password Selected", 
                                          "Password selected!\n"
                                          f"Note: Could not copy to clipboard: {str(e)}")
                else:
                    messagebox.showwarning("No Selection", "Please select a password from the list")
            except Exception as e:
                messagebox.showerror("Selection Error", f"Error selecting password: {str(e)}")
        
        def copy_all_passwords():
            try:
                all_passwords_text = "\n".join([f"{i+1}. {pwd}" for i, pwd in enumerate(passwords)])
                pyperclip.copy(all_passwords_text)
                messagebox.showinfo("All Passwords Copied", "All passwords have been copied to clipboard!")
            except Exception as e:
                messagebox.showerror("Copy Error", f"Could not copy passwords: {str(e)}")
        
        # Buttons frame
        button_frame = Frame(frame, bg='#ffffff')
        button_frame.grid(row=3, column=0, sticky="ew", pady=10)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        
        select_btn = create_modern_button(button_frame, "Use Selected Password", select_password, 
                                        "#28a745", "#218838", font=("Arial", 11))
        select_btn.grid(row=0, column=0, padx=5, sticky="ew")
        
        copy_all_btn = create_modern_button(button_frame, "Copy All", copy_all_passwords,
                                          "#6c757d", "#5a6268", font=("Arial", 11))
        copy_all_btn.grid(row=0, column=1, padx=5, sticky="ew")
        
    except Exception as e:
        messagebox.showerror("Dialog Error", f"Could not open password selection: {str(e)}")

def get_password_strength(password):
    """Calculate password strength"""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    
    if score >= 6: return "Very Strong"
    if score >= 5: return "Strong"
    if score >= 3: return "Medium"
    return "Weak"

# ---------------------------- SAVE PASSWORD ------------------------------- #
def save():
    """Save password with enhanced error handling"""
    try:
        website = website_entry.get().strip()
        email = email_entry.get().strip()
        password = password_entry.get()
        
        # Enhanced validation
        if not website:
            messagebox.showwarning("Missing Information", "Please enter a website name")
            website_entry.focus()
            return
            
        if not email:
            messagebox.showwarning("Missing Information", "Please enter an email/username")
            email_entry.focus()
            return
            
        if not password:
            messagebox.showwarning("Missing Information", "Please enter a password")
            password_entry.focus()
            return
        
        # Validate email format
        if "@" not in email or "." not in email:
            result = messagebox.askyesno("Email Validation", 
                                       "The email address doesn't look standard. Continue anyway?")
            if not result:
                email_entry.focus()
                return
        
        new_data = {
            website: {
                "email": email,
                "password": password,
            }
        }
        
        # File operations with better error handling
        try:
            # Try to read existing data
            if os.path.exists("data.json"):
                with open("data.json", "r") as data_file:
                    try:
                        data = json.load(data_file)
                    except json.JSONDecodeError:
                        # File exists but is corrupted or empty
                        data = {}
            else:
                data = {}
                
        except PermissionError:
            messagebox.showerror("Permission Denied", 
                               "Cannot access data file. Please check file permissions.")
            return
        except Exception as e:
            messagebox.showerror("File Error", f"Cannot read data file: {str(e)}")
            return
        
        # Check if website already exists
        if website in data:
            result = messagebox.askyesno("Overwrite Confirmation", 
                                       f"An entry for {website} already exists.\nOverwrite it?")
            if not result:
                return
        
        # Update data and save
        data.update(new_data)
        
        try:
            with open("data.json", "w") as data_file:
                json.dump(data, data_file, indent=4)
        except PermissionError:
            messagebox.showerror("Permission Denied", 
                               "Cannot save to data file. Please check file permissions.")
            return
        except Exception as e:
            messagebox.showerror("Save Error", f"Cannot save data: {str(e)}")
            return
        
        # Clear fields and show success
        website_entry.delete(0, END)
        password_entry.delete(0, END)
        messagebox.showinfo("Success", f"Password for {website} saved successfully!")
        
    except Exception as e:
        messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {str(e)}")

# ---------------------------- FIND PASSWORD ------------------------------- #
def find_password():
    """Find password with enhanced error handling"""
    try:
        website = website_entry.get().strip()
        
        if not website:
            messagebox.showwarning("Missing Information", "Please enter a website to search for")
            website_entry.focus()
            return
        
        # Check if file exists
        if not os.path.exists("data.json"):
            messagebox.showinfo("No Data File", "No password data file found. Save some passwords first.")
            return
        
        try:
            with open("data.json", "r") as data_file:
                try:
                    data = json.load(data_file)
                except json.JSONDecodeError:
                    messagebox.showerror("Data Error", "Password data file is corrupted or empty.")
                    return
                    
        except PermissionError:
            messagebox.showerror("Permission Denied", "Cannot access data file.")
            return
        except Exception as e:
            messagebox.showerror("File Error", f"Cannot read data file: {str(e)}")
            return
        
        # Search for website (case-insensitive)
        website_lower = website.lower()
        found_website = None
        
        for key in data.keys():
            if key.lower() == website_lower:
                found_website = key
                break
        
        if found_website:
            email = data[found_website]["email"]
            password = data[found_website]["password"]
            
            # Create a nicer display
            result_text = f"Website: {found_website}\nEmail: {email}\nPassword: {password}"
            
            # Add copy buttons in the message
            copy_result = messagebox.askyesno("Password Found", 
                                            f"{result_text}\n\nCopy password to clipboard?")
            if copy_result:
                try:
                    pyperclip.copy(password)
                    messagebox.showinfo("Copied", "Password copied to clipboard!")
                except Exception as e:
                    messagebox.showwarning("Copy Failed", f"Could not copy to clipboard: {str(e)}")
        else:
            messagebox.showinfo("Not Found", f"No details found for '{website}'")
            
    except Exception as e:
        messagebox.showerror("Search Error", f"Error searching for password: {str(e)}")

# ---------------------------- CONSISTENT BUTTON STYLE ------------------------------- #
def create_modern_button(parent, text, command, bg_color, hover_color, **kwargs):
    """Create consistently styled buttons with error handling"""
    try:
        btn = Button(
            parent,
            text=text,
            command=command,
            font=kwargs.get('font', ("Arial", 10)),
            bg=bg_color,
            fg="white",
            relief="flat",
            bd=0,
            padx=kwargs.get('padx', 15),
            pady=kwargs.get('pady', 10),
            cursor="hand2",
            width=kwargs.get('width', None)
        )
        
        # Add consistent hover effects
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_color))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg_color))
        
        return btn
    except Exception as e:
        print(f"Button creation error: {str(e)}")
        # Return a basic button as fallback
        return Button(parent, text=text, command=command)

# ---------------------------- UI SETUP ------------------------------- #

def setup_ui():
    global window, canvas, logo_img, website_entry, email_entry, password_entry
    global length_var, count_var, search_button, generate_password_button, add_button
    global avoid_similar_var, avoid_ambiguous_var
    
    try:
        # Main window configuration
        window = Tk()
        window.title("Password Manager - Enhanced")
        window.geometry("650x600")
        window.minsize(550, 500)
        window.configure(bg='#f8f9fa')

        # Configure responsive grid
        for i in range(7):
            window.rowconfigure(i, weight=1)
        for i in range(3):
            window.columnconfigure(i, weight=1)

        # Main container frame with modern styling
        main_frame = Frame(window, padx=30, pady=20, bg='#ffffff', relief='flat', bd=1)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_frame.columnconfigure(1, weight=1)

        # Configure main frame grid
        for i in range(7):
            main_frame.rowconfigure(i, weight=1)
        for i in range(3):
            main_frame.columnconfigure(i, weight=1)

        # Setup logo
        setup_logo(main_frame)
        
        # Setup labels and entries
        setup_form_elements(main_frame)
        
        # Setup password configuration
        setup_password_config(main_frame)
        
        # Setup buttons
        setup_buttons(main_frame)
        
    except Exception as e:
        messagebox.showerror("UI Setup Error", f"Failed to initialize application: {str(e)}")
        sys.exit(1)

def setup_logo(parent):
    global canvas, logo_img
    
    try:
        # Try to load the logo image
        logo_img = PhotoImage(file="logo.png")
        
        # Get the actual dimensions of the image
        img_width = logo_img.width()
        img_height = logo_img.height()
        
        # Set canvas size to match image size or use a reasonable size
        canvas_width = max(150, img_width)
        canvas_height = max(150, img_height)
        
        canvas = Canvas(parent, width=canvas_width, height=canvas_height, 
                       bg='#ffffff', highlightthickness=0)
        
        # Calculate center position
        x_center = canvas_width // 2
        y_center = canvas_height // 2
        
        # Create image at center
        canvas.create_image(x_center, y_center, image=logo_img)
        canvas.grid(row=0, column=1, pady=(0, 10), sticky="n")
        
    except Exception as e:
        # If image loading fails, create a placeholder
        print(f"Error loading logo: {e}")
        canvas = Canvas(parent, width=150, height=150, bg='#ffffff', highlightthickness=0)
        canvas.create_text(75, 75, text="🔒 Password\nManager", font=("Arial", 12, "bold"), 
                          fill='#666666', justify='center')
        canvas.grid(row=0, column=1, pady=(0, 10), sticky="n")

def setup_form_elements(parent):
    global website_entry, email_entry, password_entry
    
    try:
        # Labels with consistent styling
        label_style = {'font': ("Arial", 10), 'bg': '#ffffff', 'fg': '#495057', 'anchor': 'e'}
        
        website_label = Label(parent, text="Website:", **label_style)
        website_label.grid(row=1, column=0, sticky="e", pady=8, padx=(0, 10))
        
        email_label = Label(parent, text="Email/Username:", **label_style)
        email_label.grid(row=2, column=0, sticky="e", pady=8, padx=(0, 10))
        
        password_label = Label(parent, text="Password:", **label_style)
        password_label.grid(row=3, column=0, sticky="e", pady=8, padx=(0, 10))
        
        length_label = Label(parent, text="Password Length:", **label_style)
        length_label.grid(row=4, column=0, sticky="e", pady=8, padx=(0, 10))

        # Entry fields with consistent styling
        entry_style = {'font': ("Arial", 10), 'bg': '#f8f9fa', 'fg': '#333333', 'relief': 'flat', 'bd': 1}

        website_entry = Entry(parent, **entry_style)
        website_entry.grid(row=1, column=1, sticky="ew",  padx=(5, 0), pady=8)
        website_entry.focus()

        email_entry = Entry(parent, **entry_style)
        email_entry.grid(row=2, column=1, columnspan=2, sticky="ew",  padx=(5, 0), pady=8)
        email_entry.insert(0, "angela@email.com")

        password_entry = Entry(parent, show="*", **entry_style)
        password_entry.grid(row=3, column=1, sticky="ew",  padx=(5, 0), pady=8)
        
    except Exception as e:
        print(f"Form elements setup error: {str(e)}")

def setup_password_config(parent):
    global length_var, count_var, avoid_similar_var, avoid_ambiguous_var
    
    try:
        # Password configuration frame
        config_frame = Frame(parent, bg='#ffffff')
        config_frame.grid(row=4, column=1, columnspan=2, sticky="ew", pady=8)
        config_frame.columnconfigure(0, weight=1)
        config_frame.columnconfigure(1, weight=1)

        # Length selection - Enhanced with custom entry
        length_var = StringVar(value="16")
        length_frame = Frame(config_frame, bg='#ffffff')
        length_frame.grid(row=0, column=0, sticky="w")

        # Length options with custom entry
        length_label = Label(length_frame, text="Length:", font=("Arial", 9), 
                           bg='#ffffff', fg='#495057')
        length_label.pack(side=LEFT, padx=(0, 5))
        
        length_entry = Entry(length_frame, width=5, font=("Arial", 9), 
                           textvariable=length_var, relief='flat', bd=1)
        length_entry.pack(side=LEFT, padx=5)
        
        # Quick length buttons
        quick_lengths = [8, 12, 16, 20, 32]
        for quick_len in quick_lengths:
            btn = Button(length_frame, text=str(quick_len), font=("Arial", 8),
                        command=lambda l=quick_len: length_var.set(str(l)),
                        bg='#e9ecef', fg='#495057', relief='flat', bd=0, padx=3, pady=1)
            btn.pack(side=LEFT, padx=2)

        # Password options frame
        options_frame = Frame(config_frame, bg='#ffffff')
        options_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=5)
        
        avoid_similar_var = BooleanVar(value=True)
        avoid_ambiguous_var = BooleanVar(value=False)
        
        Checkbutton(options_frame, text="Avoid similar characters (i,l,1,o,0,O)", 
                   variable=avoid_similar_var, bg='#ffffff', font=("Arial", 8)).pack(side=LEFT, padx=5)
        
        Checkbutton(options_frame, text="Avoid ambiguous characters", 
                   variable=avoid_ambiguous_var, bg='#ffffff', font=("Arial", 8)).pack(side=LEFT, padx=5)

        # Count selection
        count_frame = Frame(config_frame, bg='#ffffff')
        count_frame.grid(row=0, column=1, sticky="e")

        count_label = Label(count_frame, text="Generate", font=("Arial", 9), bg='#ffffff', fg='#495057')
        count_label.pack(side=LEFT, padx=(0, 5))

        count_var = StringVar(value="1")
        count_spinbox = Spinbox(count_frame, from_=1, to=50, width=3, textvariable=count_var, 
                               font=("Arial", 9), bg='#f8f9fa', relief='flat', bd=1)
        count_spinbox.pack(side=LEFT, padx=5)

        count_text = Label(count_frame, text="passwords", font=("Arial", 9), bg='#ffffff', fg='#495057')
        count_text.pack(side=LEFT, padx=5)
        
    except Exception as e:
        print(f"Password config setup error: {str(e)}")

def setup_buttons(parent):
    global search_button, generate_password_button, add_button
    
    try:
        # Search Button
        search_button = create_modern_button(parent, "Search", find_password, 
                                           "#6c757d", "#5a6268", font=("Arial", 9), pady=8)
        search_button.grid(row=1, column=2, sticky="ew", padx=(5, 0), pady=8)

        # Generate Password Button
        generate_password_button = create_modern_button(parent, "Generate Password", generate_password, 
                                                      "#28a745", "#218838", font=("Arial", 9), pady=8)
        generate_password_button.grid(row=3, column=2, sticky="ew", padx=(5, 0), pady=8)

        # Add Password Button
        add_button = create_modern_button(parent, "Add Password", save, 
                                        "#007bff", "#0056b3", 
                                        font=("Arial", 11, "bold"), pady=12)
        add_button.grid(row=6, column=1, columnspan=2, sticky="ew", pady=15)
        
    except Exception as e:
        print(f"Buttons setup error: {str(e)}")

# ---------------------------- MAIN EXECUTION ------------------------------- #

if __name__ == "__main__":
    try:
        setup_ui()
        window.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application failed to start: {str(e)}")
        sys.exit(1)
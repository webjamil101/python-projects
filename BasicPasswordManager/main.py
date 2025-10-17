from tkinter import *
from tkinter import messagebox, ttk
from random import choice, randint, shuffle
import pyperclip
import json
import os
import sys
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from PIL import Image, ImageTk, ImageDraw

# ---------------------------- LOGGING SETUP ------------------------------- #

def setup_logging():
    """Setup comprehensive logging for the application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('password_manager.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ---------------------------- DATA MODELS ------------------------------- #

@dataclass
class PasswordEntry:
    website: str
    email: str
    password: str
    
    def to_dict(self) -> Dict:
        return {
            "email": self.email,
            "password": self.password
        }
    
    @classmethod
    def from_dict(cls, website: str, data: Dict) -> 'PasswordEntry':
        return cls(website, data["email"], data["password"])

@dataclass
class GenerationConfig:
    length: int
    count: int
    avoid_similar: bool
    avoid_ambiguous: bool
    use_uppercase: bool
    use_lowercase: bool
    use_numbers: bool
    use_symbols: bool

# ---------------------------- CORE SERVICES ------------------------------- #

class PasswordService:
    """Service for password generation and strength analysis"""
    
    # Character sets
    LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
    UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    NUMBERS = '0123456789'
    SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Characters to avoid
    SIMILAR_CHARS = {'i', 'l', '1', 'o', '0', 'O'}
    AMBIGUOUS_CHARS = {'{', '}', '(', ')', '[', ']', '/', '\\', '\'', '"', '`', '~', ',', '.', ';', ':'}
    
    @classmethod
    def generate_passwords(cls, config: GenerationConfig) -> List[str]:
        """Generate passwords based on configuration"""
        try:
            characters = cls._build_character_set(config)
            
            if not characters:
                raise ValueError("No character sets selected for password generation")
            
            passwords = []
            for i in range(config.count):
                password = cls._generate_single_password(config.length, characters, config)
                passwords.append(password)
            
            logger.info(f"Generated {len(passwords)} passwords with length {config.length}")
            return passwords
            
        except Exception as e:
            logger.error(f"Password generation failed: {str(e)}")
            raise
    
    @classmethod
    def _build_character_set(cls, config: GenerationConfig) -> str:
        """Build character set based on configuration"""
        characters = ""
        
        if config.use_lowercase:
            chars = cls.LOWERCASE
            if config.avoid_similar:
                chars = ''.join(c for c in chars if c not in cls.SIMILAR_CHARS)
            characters += chars
        
        if config.use_uppercase:
            chars = cls.UPPERCASE
            if config.avoid_similar:
                chars = ''.join(c for c in chars if c not in cls.SIMILAR_CHARS)
            characters += chars
        
        if config.use_numbers:
            chars = cls.NUMBERS
            if config.avoid_similar:
                chars = ''.join(c for c in chars if c not in cls.SIMILAR_CHARS)
            characters += chars
        
        if config.use_symbols:
            chars = cls.SYMBOLS
            if config.avoid_ambiguous:
                chars = ''.join(c for c in chars if c not in cls.AMBIGUOUS_CHARS)
            characters += chars
        
        return characters
    
    @classmethod
    def _generate_single_password(cls, length: int, characters: str, config: GenerationConfig) -> str:
        """Generate a single password with guaranteed character variety"""
        if len(characters) < 4:
            # Fallback to basic character set if filtered set is too small
            characters = cls.LOWERCASE + cls.UPPERCASE + cls.NUMBERS + cls.SYMBOLS
        
        # Ensure minimum requirements
        password_chars = []
        
        # Add at least one character from each selected category
        if config.use_lowercase:
            lowercase_chars = [c for c in characters if c.islower()]
            if lowercase_chars:
                password_chars.append(choice(lowercase_chars))
        
        if config.use_uppercase:
            uppercase_chars = [c for c in characters if c.isupper()]
            if uppercase_chars:
                password_chars.append(choice(uppercase_chars))
        
        if config.use_numbers:
            number_chars = [c for c in characters if c.isdigit()]
            if number_chars:
                password_chars.append(choice(number_chars))
        
        if config.use_symbols:
            symbol_chars = [c for c in characters if not c.isalnum()]
            if symbol_chars:
                password_chars.append(choice(symbol_chars))
        
        # Fill remaining length with random characters
        remaining_length = length - len(password_chars)
        if remaining_length > 0:
            password_chars.extend(choice(characters) for _ in range(remaining_length))
        
        # Shuffle to randomize positions
        shuffle(password_chars)
        
        return ''.join(password_chars)
    
    @classmethod
    def analyze_strength(cls, password: str) -> Dict[str, any]:
        """Analyze password strength and provide detailed feedback"""
        length = len(password)
        
        # Character type checks
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Common pattern checks
        is_common = password.lower() in cls._get_common_passwords()
        has_sequence = cls._has_sequence(password)
        has_repeating = cls._has_repeating_chars(password)
        
        # Calculate score
        score = 0
        if length >= 8: score += 1
        if length >= 12: score += 1
        if length >= 16: score += 2
        if has_upper: score += 1
        if has_lower: score += 1
        if has_digit: score += 1
        if has_special: score += 2
        if not is_common: score += 2
        if not has_sequence: score += 1
        if not has_repeating: score += 1
        
        # Determine strength level
        if score >= 10:
            strength = "Very Strong"
            color = "#27ae60"  # Green
        elif score >= 7:
            strength = "Strong"
            color = "#2ecc71"  # Light Green
        elif score >= 5:
            strength = "Good"
            color = "#f39c12"  # Orange
        elif score >= 3:
            strength = "Weak"
            color = "#e74c3c"  # Red
        else:
            strength = "Very Weak"
            color = "#c0392b"  # Dark Red
        
        return {
            "strength": strength,
            "color": color,
            "score": score,
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special,
            "is_common": is_common,
            "has_sequence": has_sequence,
            "has_repeating": has_repeating,
            "feedback": cls._generate_feedback(password, strength)
        }
    
    @classmethod
    def _get_common_passwords(cls) -> set:
        """Get set of common passwords (simplified version)"""
        return {
            "password", "123456", "12345678", "1234", "qwerty", "letmein",
            "admin", "welcome", "monkey", "password1", "abc123", "123123"
        }
    
    @classmethod
    def _has_sequence(cls, password: str) -> bool:
        """Check for simple sequences"""
        sequences = ["123", "abc", "qwe", "asd", "xyz"]
        password_lower = password.lower()
        return any(seq in password_lower for seq in sequences)
    
    @classmethod
    def _has_repeating_chars(cls, password: str) -> bool:
        """Check for repeating characters"""
        return any(password[i] == password[i+1] == password[i+2] 
                  for i in range(len(password) - 2))
    
    @classmethod
    def _generate_feedback(cls, password: str, strength: str) -> List[str]:
        """Generate improvement suggestions"""
        feedback = []
        length = len(password)
        
        if length < 12:
            feedback.append(f"Consider longer password (currently {length} chars)")
        
        if not any(c.isupper() for c in password):
            feedback.append("Add uppercase letters")
        
        if not any(c.islower() for c in password):
            feedback.append("Add lowercase letters")
        
        if not any(c.isdigit() for c in password):
            feedback.append("Add numbers")
        
        if not any(not c.isalnum() for c in password):
            feedback.append("Add special characters")
        
        if cls._has_sequence(password):
            feedback.append("Avoid common sequences")
        
        if cls._has_repeating_chars(password):
            feedback.append("Avoid repeating characters")
        
        if not feedback and strength != "Very Strong":
            feedback.append("Good password! Consider making it longer for maximum security")
        
        return feedback

class StorageService:
    """Service for data storage operations with enhanced error handling"""
    
    def __init__(self, filename: str = "data.json"):
        self.filename = Path(filename)
        self.backup_filename = self.filename.with_suffix('.json.backup')
        self._ensure_data_directory()
        self._ensure_data_file()
    
    def _ensure_data_directory(self):
        """Ensure the directory for data file exists"""
        try:
            self.filename.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"Ensured directory exists: {self.filename.parent}")
        except Exception as e:
            logger.error(f"Failed to create directory: {str(e)}")
            raise StorageError(f"Cannot create data directory: {str(e)}")
    
    def _ensure_data_file(self):
        """Ensure data file exists with proper structure"""
        try:
            if not self.filename.exists():
                self._write_data({})
                logger.info("Created new data file")
            else:
                # Test if existing file is readable and valid JSON
                self._test_file_readable()
        except Exception as e:
            logger.error(f"Failed to ensure data file: {str(e)}")
            raise
    
    def _test_file_readable(self):
        """Test if the data file is readable and contains valid JSON"""
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:  # Only parse if file is not empty
                    json.loads(content)
            logger.debug("Data file is readable and valid")
        except json.JSONDecodeError as e:
            logger.warning(f"Data file contains invalid JSON: {str(e)}")
            self._create_backup_and_reset()
        except Exception as e:
            logger.error(f"Data file is not readable: {str(e)}")
            raise StorageError(f"Data file is not accessible: {str(e)}")
    
    def _create_backup_and_reset(self):
        """Create backup of corrupted file and reset to empty"""
        try:
            if self.filename.exists():
                # Create backup of corrupted file
                if self.filename.stat().st_size > 0:  # Only backup if file has content
                    self.filename.rename(self.backup_filename)
                    logger.warning(f"Created backup of corrupted file: {self.backup_filename}")
                # Create new empty file
                self._write_data({})
                logger.info("Reset data file due to corruption")
        except Exception as e:
            logger.error(f"Failed to create backup and reset: {str(e)}")
            raise StorageError("Data file is corrupted and cannot be recovered")
    
    def load_all(self) -> Dict[str, PasswordEntry]:
        """Load all password entries with comprehensive error handling"""
        try:
            if not self.filename.exists():
                logger.info("Data file does not exist, returning empty dict")
                return {}
            
            # Check file permissions
            if not os.access(self.filename, os.R_OK):
                raise StorageError("No read permission for data file")
            
            with open(self.filename, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                if not content:
                    logger.info("Data file is empty")
                    return {}
                
                data = json.loads(content)
            
            # Convert to PasswordEntry objects
            entries = {}
            for website, entry_data in data.items():
                try:
                    if isinstance(entry_data, dict) and 'email' in entry_data and 'password' in entry_data:
                        entries[website] = PasswordEntry.from_dict(website, entry_data)
                    else:
                        logger.warning(f"Invalid entry format for {website}: {entry_data}")
                except Exception as e:
                    logger.error(f"Failed to parse entry for {website}: {str(e)}")
            
            logger.info(f"Loaded {len(entries)} password entries")
            return entries
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            self._create_backup_and_reset()
            raise StorageError("Data file is corrupted. It has been reset.")
        except PermissionError as e:
            logger.error(f"Permission error reading file: {str(e)}")
            raise StorageError("No permission to read the data file")
        except Exception as e:
            logger.error(f"Unexpected error loading data: {str(e)}")
            raise StorageError(f"Failed to load data: {str(e)}")
    
    def save(self, entry: PasswordEntry) -> bool:
        """Save a password entry with comprehensive error handling"""
        try:
            # Validate entry
            if not entry.website or not entry.email or not entry.password:
                raise ValueError("All fields (website, email, password) are required")
            
            # Load existing data
            data = self.load_all()
            
            # Update data
            data[entry.website] = entry.to_dict()
            
            # Save data
            success = self._write_data(data)
            
            if success:
                logger.info(f"Successfully saved entry for: {entry.website}")
                return True
            else:
                logger.error(f"Failed to save entry for: {entry.website}")
                return False
                
        except StorageError as e:
            logger.error(f"Storage error while saving: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error saving entry: {str(e)}")
            raise StorageError(f"Failed to save password: {str(e)}")
    
    def delete(self, website: str) -> bool:
        """Delete a password entry"""
        try:
            data = self.load_all()
            if website in data:
                del data[website]
                success = self._write_data(data)
                if success:
                    logger.info(f"Deleted entry for: {website}")
                    return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete entry: {str(e)}")
            return False
    
    def search(self, website: str) -> Optional[PasswordEntry]:
        """Search for a password entry (case-insensitive)"""
        try:
            data = self.load_all()
            website_lower = website.lower()
            
            for stored_website, entry_data in data.items():
                if stored_website.lower() == website_lower:
                    return PasswordEntry.from_dict(stored_website, entry_data)
            
            return None
            
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return None
    
    def _write_data(self, data: Dict) -> bool:
        """Write data to file with comprehensive error handling"""
        max_retries = 3
        temp_filename = self.filename.with_suffix('.json.tmp')
        
        for attempt in range(max_retries):
            try:
                # Check write permissions
                if self.filename.exists() and not os.access(self.filename, os.W_OK):
                    raise PermissionError("No write permission for data file")
                
                # Write to temporary file first
                with open(temp_filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                
                # Ensure the file was written successfully
                if not temp_filename.exists() or temp_filename.stat().st_size == 0:
                    raise IOError("Temporary file was not created properly")
                
                # Replace original file with temporary file
                if self.filename.exists():
                    self.filename.unlink()  # Remove old file
                temp_filename.rename(self.filename)
                
                logger.debug("Data written successfully")
                return True
                
            except PermissionError as e:
                logger.error(f"Permission error (attempt {attempt + 1}): {str(e)}")
                if attempt == max_retries - 1:
                    raise StorageError("No permission to write to data file")
                
            except IOError as e:
                logger.error(f"IO error (attempt {attempt + 1}): {str(e)}")
                if attempt == max_retries - 1:
                    raise StorageError("Failed to write data to file")
                
            except Exception as e:
                logger.error(f"Unexpected error writing data (attempt {attempt + 1}): {str(e)}")
                if attempt == max_retries - 1:
                    raise StorageError(f"Failed to save data: {str(e)}")
            
            # Clean up temporary file if it exists
            if temp_filename.exists():
                try:
                    temp_filename.unlink()
                except:
                    pass
            
            # Wait before retry
            import time
            time.sleep(0.1)
        
        return False

# ---------------------------- CUSTOM EXCEPTIONS ------------------------------- #

class StorageError(Exception):
    """Custom exception for storage operations"""
    pass

class PasswordError(Exception):
    """Custom exception for password operations"""
    pass

# ---------------------------- IMAGE SERVICE ------------------------------- #

class ImageService:
    """Service for handling images with proper scaling and formatting"""
    
    @staticmethod
    def load_logo(image_path: str, max_width: int = 120, max_height: int = 120) -> Tuple[ImageTk.PhotoImage, int, int]:
        """
        Load and resize logo image while maintaining aspect ratio
        Returns: (photo_image, actual_width, actual_height)
        """
        try:
            # Check if file exists
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Logo file not found: {image_path}")
            
            # Open and process image
            original_image = Image.open(image_path)
            
            # Calculate new dimensions while maintaining aspect ratio
            original_width, original_height = original_image.size
            ratio = min(max_width / original_width, max_height / original_height)
            new_width = int(original_width * ratio)
            new_height = int(original_height * ratio)
            
            # Resize image with high-quality resampling
            resized_image = original_image.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # Convert to PhotoImage for Tkinter
            photo_image = ImageTk.PhotoImage(resized_image)
            
            logger.info(f"Loaded logo: {image_path} ({new_width}x{new_height})")
            return photo_image, new_width, new_height
            
        except Exception as e:
            logger.error(f"Failed to load logo: {str(e)}")
            raise
    
    @staticmethod
    def create_placeholder_logo(width: int = 120, height: int = 120) -> Tuple[ImageTk.PhotoImage, int, int]:
        """Create a placeholder logo when image is not available"""
        try:
            # Create a simple placeholder image
            image = Image.new('RGB', (width, height), color='#34495e')
            draw = ImageDraw.Draw(image)
            
            # Draw a lock icon
            lock_color = '#ecf0f1'
            # Lock body
            draw.rectangle([width//2-20, height//2-15, width//2+20, height//2+20], fill=lock_color)
            # Lock arc
            draw.arc([width//2-15, height//2-25, width//2+15, height//2-5], 0, 180, fill=lock_color, width=3)
            
            # Add text
            draw.text((width//2, height//2+30), "Password", fill=lock_color, anchor="mt")
            draw.text((width//2, height//2+45), "Manager", fill=lock_color, anchor="mt")
            
            photo_image = ImageTk.PhotoImage(image)
            return photo_image, width, height
            
        except Exception as e:
            logger.error(f"Failed to create placeholder: {str(e)}")
            # Ultimate fallback - return a basic PhotoImage
            return ImageTk.PhotoImage(Image.new('RGB', (width, height), color='#34495e')), width, height

# ---------------------------- UI COMPONENTS ------------------------------- #

class ModernButton:
    """Factory for creating consistent modern buttons"""
    
    @staticmethod
    def create(parent, text: str, command, bg_color: str, hover_color: str, **kwargs) -> Button:
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
        
        # Add hover effects
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_color))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg_color))
        
        return btn

class PasswordStrengthIndicator:
    """Widget for displaying password strength"""
    
    def __init__(self, parent):
        self.frame = Frame(parent, bg='#ffffff')
        self.strength_label = Label(self.frame, text="Strength: N/A", font=("Arial", 9), bg='#ffffff')
        self.strength_bar = Canvas(self.frame, width=200, height=8, bg='#ecf0f1', highlightthickness=0)
        self.feedback_label = Label(self.frame, text="", font=("Arial", 8), bg='#ffffff', fg='#7f8c8d', wraplength=300)
        
        self.strength_label.pack(anchor='w')
        self.strength_bar.pack(anchor='w', pady=2)
        self.feedback_label.pack(anchor='w')
    
    def update_strength(self, password: str):
        """Update strength indicator based on password"""
        if not password:
            self.strength_label.config(text="Strength: N/A", fg='#7f8c8d')
            self.strength_bar.delete("all")
            self.feedback_label.config(text="")
            return
        
        analysis = PasswordService.analyze_strength(password)
        
        self.strength_label.config(
            text=f"Strength: {analysis['strength']}",
            fg=analysis['color']
        )
        
        # Update strength bar
        self.strength_bar.delete("all")
        width = min(200, (analysis['score'] / 12) * 200)  # Max score is 12
        self.strength_bar.create_rectangle(0, 0, width, 8, fill=analysis['color'], outline="")
        
        # Update feedback
        feedback_text = " • ".join(analysis['feedback']) if analysis['feedback'] else "Good password!"
        self.feedback_label.config(text=feedback_text)
    
    def grid(self, **kwargs):
        """Delegate grid to frame"""
        self.frame.grid(**kwargs)

class LogoWidget:
    """Widget for displaying the application logo"""
    
    def __init__(self, parent):
        self.parent = parent
        self.canvas = None
        self.logo_image = None
        self.logo_photo = None
        
    def load_logo(self, image_path: str = "logo.png"):
        """Load and display the logo"""
        try:
            # Load and resize logo
            self.logo_photo, width, height = ImageService.load_logo(image_path)
            
            # Create canvas with exact image dimensions
            self.canvas = Canvas(self.parent, width=width, height=height, 
                               bg='#ffffff', highlightthickness=0)
            
            # Center the image in the canvas
            x_center = width // 2
            y_center = height // 2
            
            # Display image
            self.canvas.create_image(x_center, y_center, image=self.logo_photo)
            
            logger.info(f"Logo displayed at {width}x{height}")
            
        except Exception as e:
            logger.warning(f"Using placeholder logo: {str(e)}")
            self.load_placeholder()
    
    def load_placeholder(self):
        """Load placeholder logo"""
        try:
            self.logo_photo, width, height = ImageService.create_placeholder_logo()
            
            self.canvas = Canvas(self.parent, width=width, height=height,
                               bg='#ffffff', highlightthickness=0)
            
            # Display placeholder
            self.canvas.create_image(width//2, height//2, image=self.logo_photo)
            
            logger.info("Placeholder logo displayed")
            
        except Exception as e:
            logger.error(f"Failed to create placeholder: {str(e)}")
            # Ultimate fallback - empty canvas
            self.canvas = Canvas(self.parent, width=120, height=120, 
                               bg='#ffffff', highlightthickness=0)
            self.canvas.create_text(60, 60, text="LOGO", fill='#bdc3c7', 
                                  font=("Arial", 10, "bold"))
    
    def grid(self, **kwargs):
        """Position the logo widget"""
        if self.canvas:
            self.canvas.grid(**kwargs)

# ---------------------------- MAIN APPLICATION ------------------------------- #

class PasswordManagerApp:
    """Main application class"""
    
    def __init__(self):
        self.window = None
        self.storage = StorageService()
        self.strength_indicator = None
        self.logo_widget = None
        
        # UI components
        self.website_entry = None
        self.email_entry = None
        self.password_entry = None
        self.length_var = None
        self.count_var = None
        
        # Configuration
        self.config = GenerationConfig(
            length=16,
            count=1,
            avoid_similar=True,
            avoid_ambiguous=False,
            use_uppercase=True,
            use_lowercase=True,
            use_numbers=True,
            use_symbols=True
        )
    
    def run(self):
        """Start the application"""
        try:
            self.setup_ui()
            self.window.mainloop()
        except Exception as e:
            logger.critical(f"Application failed to start: {str(e)}")
            messagebox.showerror("Fatal Error", 
                               f"Application failed to start:\n{str(e)}\n\nPlease check the logs.")
            sys.exit(1)
    
    def setup_ui(self):
        """Setup the main user interface"""
        # Main window
        self.window = Tk()
        self.window.title("🔒 Secure Password Manager")
        self.window.geometry("700x650")
        self.window.minsize(600, 550)
        self.window.configure(bg='#f8f9fa')
        
        # Center window on screen
        self.window.eval('tk::PlaceWindow . center')
        
        # Configure grid
        for i in range(8):
            self.window.rowconfigure(i, weight=1)
        for i in range(3):
            self.window.columnconfigure(i, weight=1)
        
        # Main container
        main_frame = Frame(self.window, padx=30, pady=20, bg='#ffffff', relief='flat', bd=1)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_frame.columnconfigure(1, weight=1)
        
        for i in range(8):
            main_frame.rowconfigure(i, weight=1)
        for i in range(3):
            main_frame.columnconfigure(i, weight=1)
        
        # Setup components
        self.setup_logo(main_frame)
        self.setup_form(main_frame)
        self.setup_password_config(main_frame)
        self.setup_strength_indicator(main_frame)
        self.setup_buttons(main_frame)
        
        logger.info("UI setup completed successfully")
    
    def setup_logo(self, parent):
        """Setup application logo with proper image handling"""
        self.logo_widget = LogoWidget(parent)
        self.logo_widget.load_logo("logo.png")
        self.logo_widget.grid(row=0, column=1, pady=(0, 10), sticky="n")
    
    def setup_form(self, parent):
        """Setup main form elements"""
        label_style = {'font': ("Arial", 10), 'bg': '#ffffff', 'fg': '#495057', 'anchor': 'e'}
        entry_style = {'font': ("Arial", 10), 'bg': '#f8f9fa', 'fg': '#2c3e50', 'relief': 'flat', 'bd': 1}
        
        # Website
        Label(parent, text="Website:", **label_style).grid(row=1, column=0, sticky="e", pady=8, padx=(0, 10))
        self.website_entry = Entry(parent, **entry_style)
        self.website_entry.grid(row=1, column=1, sticky="ew", pady=8, padx=(0, 5))
        self.website_entry.focus()
        self.website_entry.bind('<KeyRelease>', self._on_website_change)
        
        # Email
        Label(parent, text="Email/Username:", **label_style).grid(row=2, column=0, sticky="e", pady=8, padx=(0, 10))
        self.email_entry = Entry(parent, **entry_style)
        self.email_entry.grid(row=2, column=1, columnspan=2, sticky="ew", pady=8, padx=(0, 5))
        self.email_entry.insert(0, "user@example.com")
        
        # Password
        Label(parent, text="Password:", **label_style).grid(row=3, column=0, sticky="e", pady=8, padx=(0, 10))
        self.password_entry = Entry(parent, show="•", **entry_style)
        self.password_entry.grid(row=3, column=1, sticky="ew", pady=8, padx=(0, 5))
        self.password_entry.bind('<KeyRelease>', self._on_password_change)
    
    def setup_password_config(self, parent):
        """Setup password configuration panel"""
        config_frame = Frame(parent, bg='#ffffff')
        config_frame.grid(row=4, column=1, columnspan=2, sticky="ew", pady=8)
        config_frame.columnconfigure(0, weight=1)
        
        # Length configuration
        length_frame = Frame(config_frame, bg='#ffffff')
        length_frame.grid(row=0, column=0, sticky="w", pady=5)
        
        Label(length_frame, text="Length:", font=("Arial", 9), bg='#ffffff').pack(side=LEFT, padx=(0, 5))
        
        self.length_var = StringVar(value="16")
        length_entry = Entry(length_frame, width=4, font=("Arial", 9), textvariable=self.length_var)
        length_entry.pack(side=LEFT, padx=5)
        
        # Quick length buttons
        for length in [8, 12, 16, 20, 24]:
            Button(length_frame, text=str(length), font=("Arial", 8),
                  command=lambda l=length: self.length_var.set(str(l)),
                  bg='#e9ecef', relief='flat', padx=3, pady=1).pack(side=LEFT, padx=2)
        
        # Count configuration
        count_frame = Frame(config_frame, bg='#ffffff')
        count_frame.grid(row=1, column=0, sticky="w", pady=5)
        
        Label(count_frame, text="Generate", font=("Arial", 9), bg='#ffffff').pack(side=LEFT)
        self.count_var = StringVar(value="1")
        Spinbox(count_frame, from_=1, to=10, width=3, textvariable=self.count_var,
               font=("Arial", 9)).pack(side=LEFT, padx=5)
        Label(count_frame, text="passwords", font=("Arial", 9), bg='#ffffff').pack(side=LEFT)
    
    def setup_strength_indicator(self, parent):
        """Setup password strength indicator"""
        self.strength_indicator = PasswordStrengthIndicator(parent)
        self.strength_indicator.grid(row=5, column=1, columnspan=2, sticky="w", pady=10)
    
    def setup_buttons(self, parent):
        """Setup action buttons"""
        # Search button
        search_btn = ModernButton.create(parent, "🔍 Search", self.search_password,
                                       "#3498db", "#2980b9", font=("Arial", 9))
        search_btn.grid(row=1, column=2, sticky="ew", padx=(5, 0), pady=8)
        
        # Generate button
        generate_btn = ModernButton.create(parent, "⚡ Generate", self.generate_password,
                                         "#27ae60", "#229954", font=("Arial", 9))
        generate_btn.grid(row=3, column=2, sticky="ew", padx=(5, 0), pady=8)
        
        # Add button
        add_btn = ModernButton.create(parent, "💾 Save Password", self.save_password,
                                    "#e74c3c", "#c0392b", font=("Arial", 11, "bold"), pady=12)
        add_btn.grid(row=7, column=1, columnspan=2, sticky="ew", pady=15)
    
    def _on_password_change(self, event=None):
        """Handle password field changes"""
        password = self.password_entry.get()
        self.strength_indicator.update_strength(password)
    
    def _on_website_change(self, event=None):
        """Handle website field changes"""
        # Auto-focus password field when website is entered
        if self.website_entry.get() and not self.password_entry.get():
            self.password_entry.focus()
    
    def generate_password(self):
        """Generate passwords based on current configuration"""
        try:
            # Update config from UI
            self.config.length = int(self.length_var.get())
            self.config.count = int(self.count_var.get())
            
            # Validate inputs
            if self.config.length < 4 or self.config.length > 100:
                messagebox.showwarning("Invalid Length", "Password length must be between 4-100 characters")
                return
            
            if self.config.count < 1 or self.config.count > 10:
                messagebox.showwarning("Invalid Count", "Can generate 1-10 passwords at once")
                return
            
            # Generate passwords
            passwords = PasswordService.generate_passwords(self.config)
            
            if self.config.count == 1:
                # Single password - insert directly
                self.password_entry.delete(0, END)
                self.password_entry.insert(0, passwords[0])
                self._on_password_change()  # Update strength indicator
                
                try:
                    pyperclip.copy(passwords[0])
                    messagebox.showinfo("Success", "Password generated and copied to clipboard! ✅")
                except Exception as e:
                    messagebox.showinfo("Success", "Password generated! (Clipboard unavailable)")
            else:
                # Multiple passwords - show selection dialog
                self._show_password_selection(passwords)
                
        except ValueError as e:
            messagebox.showerror("Input Error", "Please enter valid numbers for length and count")
        except Exception as e:
            logger.error(f"Password generation failed: {str(e)}")
            messagebox.showerror("Generation Error", f"Failed to generate passwords:\n{str(e)}")
    
    def _show_password_selection(self, passwords: List[str]):
        """Show password selection dialog"""
        selection_window = Toplevel(self.window)
        selection_window.title("Select Password")
        selection_window.geometry("500x400")
        selection_window.transient(self.window)
        selection_window.grab_set()
        selection_window.configure(bg='#ffffff')
        
        # Header
        header_frame = Frame(selection_window, bg='#ffffff', padx=20, pady=10)
        header_frame.pack(fill=X)
        
        Label(header_frame, text="Choose a Password", font=("Arial", 16, "bold"),
              bg='#ffffff').pack(anchor='w')
        
        Label(header_frame, text=f"{len(passwords)} passwords generated • {len(passwords[0])} characters each",
              font=("Arial", 10), bg='#ffffff', fg='#7f8c8d').pack(anchor='w', pady=(5, 0))
        
        # Listbox with scrollbar
        list_frame = Frame(selection_window, bg='#ffffff')
        list_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        listbox = Listbox(list_frame, font=("Consolas", 11), bg='#f8f9fa', 
                         selectbackground='#3498db', selectforeground='white')
        scrollbar = Scrollbar(list_frame)
        
        listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=listbox.yview)
        
        listbox.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # Add passwords with strength indicators
        for i, password in enumerate(passwords, 1):
            strength = PasswordService.analyze_strength(password)['strength']
            listbox.insert(END, f"{i:2d}. {password} [{strength}]")
        
        # Buttons
        button_frame = Frame(selection_window, bg='#ffffff', padx=20, pady=10)
        button_frame.pack(fill=X)
        
        def select_password():
            selection = listbox.curselection()
            if selection:
                selected_password = passwords[selection[0]]
                self.password_entry.delete(0, END)
                self.password_entry.insert(0, selected_password)
                self._on_password_change()
                selection_window.destroy()
                messagebox.showinfo("Selected", "Password selected! ✅")
            else:
                messagebox.showwarning("Selection", "Please select a password")
        
        Button(button_frame, text="Select", command=select_password,
               bg='#27ae60', fg='white', relief='flat', padx=20, pady=8).pack(side=LEFT)
        
        Button(button_frame, text="Cancel", command=selection_window.destroy,
               bg='#95a5a6', fg='white', relief='flat', padx=20, pady=8).pack(side=LEFT, padx=5)
    
    def search_password(self):
        """Search for saved password"""
        try:
            website = self.website_entry.get().strip()
            if not website:
                messagebox.showwarning("Input Required", "Please enter a website to search for")
                return
            
            entry = self.storage.search(website)
            if entry:
                self.email_entry.delete(0, END)
                self.email_entry.insert(0, entry.email)
                self.password_entry.delete(0, END)
                self.password_entry.insert(0, entry.password)
                self._on_password_change()
                
                messagebox.showinfo("Found", f"Credentials found for {entry.website} ✅")
            else:
                messagebox.showinfo("Not Found", f"No saved credentials for '{website}'")
                
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            messagebox.showerror("Search Error", f"Search failed:\n{str(e)}")
    
    def save_password(self):
        """Save current credentials with comprehensive error handling"""
        try:
            website = self.website_entry.get().strip()
            email = self.email_entry.get().strip()
            password = self.password_entry.get()
            
            # Enhanced validation
            if not website:
                messagebox.showwarning("Missing Information", "Please enter a website name")
                self.website_entry.focus()
                return
            
            if not email:
                messagebox.showwarning("Missing Information", "Please enter an email/username")
                self.email_entry.focus()
                return
            
            if not password:
                messagebox.showwarning("Missing Information", "Please enter a password")
                self.password_entry.focus()
                return
            
            # Validate email format (basic check)
            if "@" not in email or "." not in email:
                result = messagebox.askyesno(
                    "Email Validation", 
                    f"The email '{email}' doesn't look standard.\nContinue anyway?"
                )
                if not result:
                    self.email_entry.focus()
                    return
            
            # Check for existing entry
            existing_entry = self.storage.search(website)
            if existing_entry:
                result = messagebox.askyesno(
                    "Overwrite Confirmation",
                    f"An entry for '{website}' already exists.\nOverwrite it?"
                )
                if not result:
                    return
            
            # Create and save entry
            entry = PasswordEntry(website, email, password)
            
            try:
                success = self.storage.save(entry)
                
                if success:
                    # Clear form for next entry
                    self.website_entry.delete(0, END)
                    self.password_entry.delete(0, END)
                    self._on_password_change()  # Update strength indicator
                    
                    messagebox.showinfo(
                        "Success ✅", 
                        f"Password for '{website}' saved successfully!\n\n"
                        f"Email: {email}\n"
                        f"Password length: {len(password)} characters"
                    )
                else:
                    messagebox.showerror(
                        "Save Failed ❌", 
                        "Failed to save password. Please check:\n"
                        "• File permissions\n"
                        "• Available disk space\n"
                        "• Data file integrity"
                    )
                    
            except StorageError as e:
                logger.error(f"Storage error during save: {str(e)}")
                messagebox.showerror(
                    "Storage Error ❌",
                    f"Could not save password:\n{str(e)}\n\n"
                    "Please check if the application has write permissions."
                )
                
        except Exception as e:
            logger.error(f"Unexpected error during save: {str(e)}")
            messagebox.showerror(
                "Unexpected Error ❌",
                f"An unexpected error occurred:\n{str(e)}\n\n"
                "Please check the application logs for details."
            )

# ---------------------------- MAIN EXECUTION ------------------------------- #

if __name__ == "__main__":
    try:
        app = PasswordManagerApp()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        messagebox.showerror("Fatal Error", "Application encountered a fatal error and must close.")
        sys.exit(1)
import os

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header(title):
    """Display a formatted header"""
    clear_screen()
    print("=" * 60)
    print(f"{'TIC TAC TOE':^60}")
    print("=" * 60)
    print(f"{title:^60}")
    print("-" * 60)

def validate_input(prompt, input_type=int, valid_range=None):
    """Validate user input"""
    while True:
        try:
            user_input = input(prompt)
            if input_type == int:
                user_input = int(user_input)
            elif input_type == str:
                user_input = str(user_input).strip()
            
            if valid_range:
                if user_input in valid_range:
                    return user_input
                else:
                    print(f"Please enter a value between {valid_range[0]} and {valid_range[-1]}")
            else:
                return user_input
        except ValueError:
            print("Invalid input! Please try again.")

def print_colored(text, color_code):
    """Print colored text"""
    color_codes = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'reset': '\033[0m'
    }
    return f"{color_codes.get(color_code, '')}{text}{color_codes.get('reset', '')}"
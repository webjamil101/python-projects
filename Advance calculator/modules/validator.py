import re
import math

class Validator:
    """Input validation and expression parsing"""
    
    @staticmethod
    def validate_number(input_str):
        """Validate if input is a valid number"""
        try:
            # Handle percentage input
            if input_str.endswith('%'):
                return float(input_str[:-1]) / 100
            
            # Handle scientific notation
            if 'e' in input_str.lower():
                return float(input_str)
            
            # Handle regular numbers
            return float(input_str)
        except ValueError:
            raise ValueError(f"Invalid number: {input_str}")
    
    @staticmethod
    def validate_positive_number(input_str):
        """Validate if input is a positive number"""
        num = Validator.validate_number(input_str)
        if num < 0:
            raise ValueError("Number must be positive")
        return num
    
    @staticmethod
    def validate_integer(input_str):
        """Validate if input is an integer"""
        try:
            return int(input_str)
        except ValueError:
            raise ValueError(f"Invalid integer: {input_str}")
    
    @staticmethod
    def validate_angle_range(angle, degrees=True):
        """Validate angle is in reasonable range"""
        if degrees:
            if abs(angle) > 360 * 10:  # Allow up to 10 full rotations
                raise ValueError("Angle value too large")
        else:
            if abs(angle) > 2 * math.pi * 10:  # Allow up to 10 full rotations
                raise ValueError("Angle value too large")
        return angle
    
    @staticmethod
    def validate_division_by_zero(divisor):
        """Check for division by zero"""
        if divisor == 0:
            raise ValueError("Division by zero is not allowed")
        return True
    
    @staticmethod
    def validate_log_input(value):
        """Validate input for logarithmic functions"""
        if value <= 0:
            raise ValueError("Logarithm input must be positive")
        return True
    
    @staticmethod
    def validate_sqrt_input(value):
        """Validate input for square root"""
        if value < 0:
            raise ValueError("Square root of negative number is not real")
        return True
    
    @staticmethod
    def validate_factorial_input(value):
        """Validate input for factorial"""
        if value < 0:
            raise ValueError("Factorial of negative number is not defined")
        if value != int(value):
            raise ValueError("Factorial requires integer input")
        if value > 1000:  # Reasonable limit to prevent excessive computation
            raise ValueError("Factorial input too large")
        return int(value)
    
    @staticmethod
    def validate_financial_inputs(*args):
        """Validate financial calculation inputs"""
        for arg in args:
            if arg < 0:
                raise ValueError("Financial inputs cannot be negative")
        return True
    
    @staticmethod
    def parse_expression(expression):
        """Parse mathematical expression (basic implementation)"""
        # Remove spaces
        expression = expression.replace(' ', '')
        
        # Validate characters
        valid_chars = set('0123456789.+-*/^()% ')
        if not all(c in valid_chars for c in expression):
            raise ValueError("Invalid characters in expression")
        
        # Basic safety check - prevent code injection
        dangerous_patterns = ['__', 'import', 'exec', 'eval']
        for pattern in dangerous_patterns:
            if pattern in expression.lower():
                raise ValueError("Invalid expression")
        
        return expression
    
    @staticmethod
    def validate_list_input(numbers_str):
        """Validate comma-separated list of numbers"""
        if not numbers_str.strip():
            raise ValueError("Empty input")
        
        numbers = []
        for num_str in numbers_str.split(','):
            try:
                numbers.append(float(num_str.strip()))
            except ValueError:
                raise ValueError(f"Invalid number in list: {num_str}")
        
        return numbers
    
    @staticmethod
    def validate_conversion_units(from_unit, to_unit, valid_units):
        """Validate conversion units"""
        if from_unit not in valid_units:
            raise ValueError(f"Invalid source unit: {from_unit}")
        if to_unit not in valid_units:
            raise ValueError(f"Invalid target unit: {to_unit}")
        return True
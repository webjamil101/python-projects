import math

class ScientificOperations:
    """Scientific operations including trigonometric, logarithmic, and statistical functions"""
    
    # Trigonometric functions
    @staticmethod
    def sin(x, degrees=False):
        """Sine function"""
        if degrees:
            x = math.radians(x)
        return math.sin(x)
    
    @staticmethod
    def cos(x, degrees=False):
        """Cosine function"""
        if degrees:
            x = math.radians(x)
        return math.cos(x)
    
    @staticmethod
    def tan(x, degrees=False):
        """Tangent function"""
        if degrees:
            x = math.radians(x)
        return math.tan(x)
    
    @staticmethod
    def asin(x, degrees=False):
        """Inverse sine function"""
        if x < -1 or x > 1:
            raise ValueError("Error: Input must be between -1 and 1")
        result = math.asin(x)
        return math.degrees(result) if degrees else result
    
    @staticmethod
    def acos(x, degrees=False):
        """Inverse cosine function"""
        if x < -1 or x > 1:
            raise ValueError("Error: Input must be between -1 and 1")
        result = math.acos(x)
        return math.degrees(result) if degrees else result
    
    @staticmethod
    def atan(x, degrees=False):
        """Inverse tangent function"""
        result = math.atan(x)
        return math.degrees(result) if degrees else result
    
    # Logarithmic functions
    @staticmethod
    def log(x, base=10):
        """Logarithm with custom base"""
        if x <= 0:
            raise ValueError("Error: Logarithm input must be positive")
        if base <= 0 or base == 1:
            raise ValueError("Error: Logarithm base must be positive and not equal to 1")
        return math.log(x, base)
    
    @staticmethod
    def ln(x):
        """Natural logarithm"""
        if x <= 0:
            raise ValueError("Error: Natural logarithm input must be positive")
        return math.log(x)
    
    @staticmethod
    def log10(x):
        """Base-10 logarithm"""
        if x <= 0:
            raise ValueError("Error: Logarithm input must be positive")
        return math.log10(x)
    
    # Exponential functions
    @staticmethod
    def exp(x):
        """Exponential function e^x"""
        return math.exp(x)
    
    @staticmethod
    def exp10(x):
        """10^x function"""
        return 10 ** x
    
    # Hyperbolic functions
    @staticmethod
    def sinh(x):
        """Hyperbolic sine"""
        return math.sinh(x)
    
    @staticmethod
    def cosh(x):
        """Hyperbolic cosine"""
        return math.cosh(x)
    
    @staticmethod
    def tanh(x):
        """Hyperbolic tangent"""
        return math.tanh(x)
    
    # Constants
    @staticmethod
    def pi():
        """Pi constant"""
        return math.pi
    
    @staticmethod
    def e():
        """Euler's number"""
        return math.e
    
    # Statistical functions
    @staticmethod
    def mean(numbers):
        """Calculate mean of a list of numbers"""
        if not numbers:
            raise ValueError("Error: Cannot calculate mean of empty list")
        return sum(numbers) / len(numbers)
    
    @staticmethod
    def median(numbers):
        """Calculate median of a list of numbers"""
        if not numbers:
            raise ValueError("Error: Cannot calculate median of empty list")
        sorted_numbers = sorted(numbers)
        n = len(sorted_numbers)
        if n % 2 == 0:
            return (sorted_numbers[n//2 - 1] + sorted_numbers[n//2]) / 2
        else:
            return sorted_numbers[n//2]
    
    @staticmethod
    def standard_deviation(numbers):
        """Calculate standard deviation"""
        if len(numbers) < 2:
            raise ValueError("Error: At least 2 numbers required for standard deviation")
        mean = sum(numbers) / len(numbers)
        variance = sum((x - mean) ** 2 for x in numbers) / (len(numbers) - 1)
        return math.sqrt(variance)
class BasicOperations:
    """Basic arithmetic operations"""
    
    @staticmethod
    def add(a, b):
        """Addition"""
        return a + b
    
    @staticmethod
    def subtract(a, b):
        """Subtraction"""
        return a - b
    
    @staticmethod
    def multiply(a, b):
        """Multiplication"""
        return a * b
    
    @staticmethod
    def divide(a, b):
        """Division with zero check"""
        if b == 0:
            raise ValueError("Error: Division by zero is not allowed")
        return a / b
    
    @staticmethod
    def power(a, b):
        """Exponentiation"""
        return a ** b
    
    @staticmethod
    def square_root(a):
        """Square root"""
        if a < 0:
            raise ValueError("Error: Square root of negative number is not real")
        return a ** 0.5
    
    @staticmethod
    def percentage(a, b):
        """Calculate percentage: a% of b"""
        return (a / 100) * b
    
    @staticmethod
    def modulus(a, b):
        """Modulus operation"""
        if b == 0:
            raise ValueError("Error: Modulus by zero is not allowed")
        return a % b
    
    @staticmethod
    def factorial(n):
        """Factorial calculation"""
        if n < 0:
            raise ValueError("Error: Factorial of negative number is not defined")
        if n == 0 or n == 1:
            return 1
        result = 1
        for i in range(2, int(n) + 1):
            result *= i
        return result
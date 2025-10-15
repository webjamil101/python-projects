import math

class FinancialOperations:
    """Financial calculations including interest, loans, and investments"""
    
    @staticmethod
    def simple_interest(principal, rate, time):
        """Calculate simple interest"""
        if principal <= 0 or rate < 0 or time < 0:
            raise ValueError("Error: Principal, rate, and time must be positive")
        return principal * rate * time / 100
    
    @staticmethod
    def compound_interest(principal, rate, time, compounding_frequency=1):
        """Calculate compound interest"""
        if principal <= 0 or rate < 0 or time < 0 or compounding_frequency <= 0:
            raise ValueError("Error: All inputs must be positive")
        
        amount = principal * (1 + rate / (100 * compounding_frequency)) ** (compounding_frequency * time)
        return amount - principal
    
    @staticmethod
    def future_value(present_value, rate, periods):
        """Calculate future value of an investment"""
        if present_value <= 0 or rate < 0 or periods < 0:
            raise ValueError("Error: All inputs must be positive")
        return present_value * (1 + rate / 100) ** periods
    
    @staticmethod
    def present_value(future_value, rate, periods):
        """Calculate present value of a future amount"""
        if future_value <= 0 or rate < 0 or periods < 0:
            raise ValueError("Error: All inputs must be positive")
        return future_value / (1 + rate / 100) ** periods
    
    @staticmethod
    def loan_payment(principal, annual_rate, years, payments_per_year=12):
        """Calculate loan payment using amortization formula"""
        if principal <= 0 or annual_rate < 0 or years <= 0 or payments_per_year <= 0:
            raise ValueError("Error: All inputs must be positive")
        
        total_payments = years * payments_per_year
        monthly_rate = annual_rate / (100 * payments_per_year)
        
        if monthly_rate == 0:
            return principal / total_payments
        
        payment = (principal * monthly_rate) / (1 - (1 + monthly_rate) ** -total_payments)
        return payment
    
    @staticmethod
    def mortgage_payment(principal, annual_rate, years):
        """Calculate mortgage payment (alias for loan_payment)"""
        return FinancialOperations.loan_payment(principal, annual_rate, years)
    
    @staticmethod
    def roi(initial_investment, final_value):
        """Calculate Return on Investment (ROI)"""
        if initial_investment <= 0:
            raise ValueError("Error: Initial investment must be positive")
        return ((final_value - initial_investment) / initial_investment) * 100
    
    @staticmethod
    def net_present_value(cash_flows, discount_rate):
        """Calculate Net Present Value (NPV)"""
        if not cash_flows:
            raise ValueError("Error: Cash flows list cannot be empty")
        
        npv = 0
        for i, cash_flow in enumerate(cash_flows):
            npv += cash_flow / (1 + discount_rate / 100) ** i
        return npv
    
    @staticmethod
    def emi_calculation(principal, annual_rate, tenure_months):
        """Calculate Equated Monthly Installment (EMI)"""
        if principal <= 0 or annual_rate < 0 or tenure_months <= 0:
            raise ValueError("Error: All inputs must be positive")
        
        monthly_rate = annual_rate / (12 * 100)
        emi = (principal * monthly_rate * (1 + monthly_rate) ** tenure_months) / ((1 + monthly_rate) ** tenure_months - 1)
        return emi
    
    @staticmethod
    def effective_annual_rate(nominal_rate, compounding_frequency):
        """Calculate Effective Annual Rate (EAR)"""
        if nominal_rate < 0 or compounding_frequency <= 0:
            raise ValueError("Error: Rate must be non-negative and frequency positive")
        return ((1 + nominal_rate / (100 * compounding_frequency)) ** compounding_frequency - 1) * 100
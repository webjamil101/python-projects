"""
Advanced Calculator - Main Application
"""

import sys
import os

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    # Import all modules
    from modules import (
        BasicOperations, ScientificOperations, FinancialOperations, 
        ConversionOperations, HistoryManager, MemoryManager, 
        Validator, Display
    )
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please make sure all module files are in the 'modules' directory.")
    sys.exit(1)

class AdvancedCalculator:
    def __init__(self):
        self.basic_ops = BasicOperations()
        self.scientific_ops = ScientificOperations()
        self.financial_ops = FinancialOperations()
        self.conversion_ops = ConversionOperations()
        self.history_manager = HistoryManager()
        self.memory_manager = MemoryManager()
        self.validator = Validator()
        self.display = Display()
        
        self.current_result = 0
        self.last_operation = ""
    
    def main_menu(self):
        """Display main menu"""
        while True:
            self.display.display_header("MAIN MENU")
            print("1. Basic Calculator")
            print("2. Scientific Calculator")
            print("3. Financial Calculator")
            print("4. Unit Converter")
            print("5. Memory Functions")
            print("6. History & Statistics")
            print("7. Help")
            print("8. Exit")
            
            try:
                choice = input("\nEnter your choice (1-8): ").strip()
                
                if choice == '1':
                    self.basic_calculator()
                elif choice == '2':
                    self.scientific_calculator()
                elif choice == '3':
                    self.financial_calculator()
                elif choice == '4':
                    self.unit_converter()
                elif choice == '5':
                    self.memory_functions()
                elif choice == '6':
                    self.history_functions()
                elif choice == '7':
                    self.show_help()
                elif choice == '8':
                    print("\nThank you for using the Advanced Calculator!")
                    break
                else:
                    print("Invalid choice! Please try again.")
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nCalculator session ended.")
                break
            except Exception as e:
                self.display.display_error(str(e))
                input("Press Enter to continue...")
    
    def basic_calculator(self):
        """Basic calculator operations"""
        self.display.display_header("BASIC CALCULATOR")
        
        print("Available operations: +, -, *, /, ^ (power), % (percentage), ! (factorial), √ (square root)")
        print("Enter 'back' to return to main menu")
        
        while True:
            try:
                print(f"\nCurrent result: {self.current_result}")
                expression = input("\nEnter expression (e.g., 5 + 3): ").strip()
                
                if expression.lower() == 'back':
                    break
                if not expression:
                    continue
                
                # Handle single number operations
                if expression in ['√', '!']:
                    num = self.validator.validate_number(input("Enter number: "))
                    
                    if expression == '√':
                        self.validator.validate_sqrt_input(num)
                        result = self.basic_ops.square_root(num)
                        operation = f"√{num}"
                    else:  # factorial
                        num = self.validator.validate_factorial_input(num)
                        result = self.basic_ops.factorial(num)
                        operation = f"{num}!"
                    
                    self.display.display_result(operation, operation, result)
                    self.history_manager.add_record(operation, operation, result, 'basic')
                    self.current_result = result
                    
                elif '%' in expression:
                    # Percentage calculation
                    parts = expression.split('%')
                    if len(parts) == 2 and 'of' in parts[1]:
                        num_parts = parts[1].split('of')
                        percentage = self.validator.validate_number(parts[0])
                        number = self.validator.validate_number(num_parts[1])
                        result = self.basic_ops.percentage(percentage, number)
                        operation = f"{percentage}% of {number}"
                        self.display.display_result("Percentage", operation, result)
                        self.history_manager.add_record("Percentage", operation, result, 'basic')
                        self.current_result = result
                    else:
                        print("Use format: '25% of 200'")
                
                else:
                    # Basic arithmetic
                    operators = ['+', '-', '*', '/', '^']
                    found_operator = None
                    for op in operators:
                        if op in expression:
                            found_operator = op
                            break
                    
                    if found_operator:
                        parts = expression.split(found_operator)
                        if len(parts) == 2:
                            a = self.validator.validate_number(parts[0])
                            b = self.validator.validate_number(parts[1])
                            
                            if found_operator == '+':
                                result = self.basic_ops.add(a, b)
                            elif found_operator == '-':
                                result = self.basic_ops.subtract(a, b)
                            elif found_operator == '*':
                                result = self.basic_ops.multiply(a, b)
                            elif found_operator == '/':
                                self.validator.validate_division_by_zero(b)
                                result = self.basic_ops.divide(a, b)
                            elif found_operator == '^':
                                result = self.basic_ops.power(a, b)
                            
                            self.display.display_result(found_operator, expression, result)
                            self.history_manager.add_record(found_operator, expression, result, 'basic')
                            self.current_result = result
                        else:
                            self.display.display_error("Invalid expression format")
                    else:
                        self.display.display_error("No valid operator found")
                
                # Ask if user wants to continue
                continue_calc = input("\nPerform another calculation? (y/n): ").lower()
                if continue_calc != 'y':
                    break
                    
            except ValueError as e:
                self.display.display_error(str(e))
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.display.display_error(f"Calculation error: {e}")
    
    def scientific_calculator(self):
        """Scientific calculator operations"""
        self.display.display_header("SCIENTIFIC CALCULATOR")
        
        print("Available functions: sin, cos, tan, log, ln, exp, mean, median, std")
        print("Use 'd' for degrees or 'r' for radians in trigonometric functions")
        print("Enter 'back' to return to main menu")
        
        while True:
            try:
                print(f"\nCurrent result: {self.current_result}")
                print("\n1. Trigonometric")
                print("2. Logarithmic")
                print("3. Statistical")
                print("4. Constants")
                print("5. Back to Main Menu")
                
                choice = input("\nEnter choice (1-5): ").strip()
                
                if choice == '5' or choice.lower() == 'back':
                    break
                
                elif choice == '1':
                    # Trigonometric functions
                    print("\nTrigonometric Functions: sin, cos, tan, asin, acos, atan")
                    func = input("Enter function: ").strip().lower()
                    angle = self.validator.validate_number(input("Enter angle: "))
                    unit = input("Degrees (d) or Radians (r)? ").strip().lower()
                    
                    degrees = (unit == 'd')
                    self.validator.validate_angle_range(angle, degrees)
                    
                    if func == 'sin':
                        result = self.scientific_ops.sin(angle, degrees)
                    elif func == 'cos':
                        result = self.scientific_ops.cos(angle, degrees)
                    elif func == 'tan':
                        result = self.scientific_ops.tan(angle, degrees)
                    elif func == 'asin':
                        result = self.scientific_ops.asin(angle, degrees)
                    elif func == 'acos':
                        result = self.scientific_ops.acos(angle, degrees)
                    elif func == 'atan':
                        result = self.scientific_ops.atan(angle, degrees)
                    else:
                        self.display.display_error("Invalid trigonometric function")
                        continue
                    
                    unit_str = "°" if degrees else " rad"
                    expression = f"{func}({angle}{unit_str})"
                    self.display.display_result(func, expression, result)
                    self.history_manager.add_record(func, expression, result, 'scientific')
                    self.current_result = result
                
                elif choice == '2':
                    # Logarithmic functions
                    print("\nLogarithmic Functions: log, ln, log10, exp, exp10")
                    func = input("Enter function: ").strip().lower()
                    x = self.validator.validate_number(input("Enter value: "))
                    
                    if func in ['log', 'ln', 'log10']:
                        self.validator.validate_log_input(x)
                    
                    if func == 'log':
                        base = self.validator.validate_number(input("Enter base: "))
                        result = self.scientific_ops.log(x, base)
                        expression = f"log_{base}({x})"
                    elif func == 'ln':
                        result = self.scientific_ops.ln(x)
                        expression = f"ln({x})"
                    elif func == 'log10':
                        result = self.scientific_ops.log10(x)
                        expression = f"log10({x})"
                    elif func == 'exp':
                        result = self.scientific_ops.exp(x)
                        expression = f"exp({x})"
                    elif func == 'exp10':
                        result = self.scientific_ops.exp10(x)
                        expression = f"10^{x}"
                    else:
                        self.display.display_error("Invalid logarithmic function")
                        continue
                    
                    self.display.display_result(func, expression, result)
                    self.history_manager.add_record(func, expression, result, 'scientific')
                    self.current_result = result
                
                elif choice == '3':
                    # Statistical functions
                    print("\nStatistical Functions: mean, median, std")
                    func = input("Enter function: ").strip().lower()
                    numbers_str = input("Enter numbers (comma-separated): ")
                    
                    numbers = self.validator.validate_list_input(numbers_str)
                    
                    if func == 'mean':
                        result = self.scientific_ops.mean(numbers)
                    elif func == 'median':
                        result = self.scientific_ops.median(numbers)
                    elif func == 'std':
                        result = self.scientific_ops.standard_deviation(numbers)
                    else:
                        self.display.display_error("Invalid statistical function")
                        continue
                    
                    expression = f"{func}({numbers_str})"
                    self.display.display_result(func, expression, result)
                    self.history_manager.add_record(func, expression, result, 'statistical')
                    self.current_result = result
                
                elif choice == '4':
                    # Constants
                    constants = self.scientific_ops.pi(), self.scientific_ops.e()
                    print(f"\nMathematical Constants:")
                    print(f"π (pi) = {constants[0]}")
                    print(f"e = {constants[1]}")
                    input("\nPress Enter to continue...")
                
                else:
                    self.display.display_error("Invalid choice")
                
                continue_calc = input("\nPerform another scientific calculation? (y/n): ").lower()
                if continue_calc != 'y':
                    break
                    
            except ValueError as e:
                self.display.display_error(str(e))
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.display.display_error(f"Scientific calculation error: {e}")
    
    def financial_calculator(self):
        """Financial calculator operations"""
        self.display.display_header("FINANCIAL CALCULATOR")
        
        print("Available calculations: simple interest, compound interest, loan payment, ROI, NPV, EMI")
        print("Enter 'back' to return to main menu")
        
        while True:
            try:
                print(f"\nCurrent result: {self.current_result}")
                print("\n1. Simple Interest")
                print("2. Compound Interest")
                print("3. Loan Payment")
                print("4. ROI (Return on Investment)")
                print("5. NPV (Net Present Value)")
                print("6. EMI Calculation")
                print("7. Back to Main Menu")
                
                choice = input("\nEnter choice (1-7): ").strip()
                
                if choice == '7' or choice.lower() == 'back':
                    break
                
                elif choice == '1':
                    # Simple Interest
                    principal = self.validator.validate_positive_number(input("Principal amount: "))
                    rate = self.validator.validate_positive_number(input("Annual interest rate (%): "))
                    time = self.validator.validate_positive_number(input("Time (years): "))
                    
                    result = self.financial_ops.simple_interest(principal, rate, time)
                    expression = f"Simple Interest on {principal} at {rate}% for {time} years"
                    self.display.display_result("Simple Interest", expression, result)
                    self.history_manager.add_record("Simple Interest", expression, result, 'financial')
                    self.current_result = result
                
                elif choice == '2':
                    # Compound Interest
                    principal = self.validator.validate_positive_number(input("Principal amount: "))
                    rate = self.validator.validate_positive_number(input("Annual interest rate (%): "))
                    time = self.validator.validate_positive_number(input("Time (years): "))
                    frequency = self.validator.validate_positive_number(input("Compounding frequency per year: "))
                    
                    result = self.financial_ops.compound_interest(principal, rate, time, frequency)
                    expression = f"Compound Interest on {principal} at {rate}% for {time} years"
                    self.display.display_result("Compound Interest", expression, result)
                    self.history_manager.add_record("Compound Interest", expression, result, 'financial')
                    self.current_result = result
                
                elif choice == '3':
                    # Loan Payment
                    principal = self.validator.validate_positive_number(input("Loan amount: "))
                    rate = self.validator.validate_positive_number(input("Annual interest rate (%): "))
                    years = self.validator.validate_positive_number(input("Loan term (years): "))
                    
                    result = self.financial_ops.loan_payment(principal, rate, years)
                    expression = f"Loan Payment for {principal} at {rate}% for {years} years"
                    self.display.display_result("Loan Payment", expression, result)
                    self.history_manager.add_record("Loan Payment", expression, result, 'financial')
                    self.current_result = result
                
                elif choice == '4':
                    # ROI
                    initial = self.validator.validate_positive_number(input("Initial investment: "))
                    final = self.validator.validate_positive_number(input("Final value: "))
                    
                    result = self.financial_ops.roi(initial, final)
                    expression = f"ROI from {initial} to {final}"
                    self.display.display_result("ROI", expression, f"{result}%")
                    self.history_manager.add_record("ROI", expression, f"{result}%", 'financial')
                    self.current_result = result
                
                elif choice == '5':
                    # NPV
                    cash_flows_str = input("Enter cash flows (comma-separated): ")
                    cash_flows = self.validator.validate_list_input(cash_flows_str)
                    discount_rate = self.validator.validate_positive_number(input("Discount rate (%): "))
                    
                    result = self.financial_ops.net_present_value(cash_flows, discount_rate)
                    expression = f"NPV of {cash_flows} at {discount_rate}%"
                    self.display.display_result("NPV", expression, result)
                    self.history_manager.add_record("NPV", expression, result, 'financial')
                    self.current_result = result
                
                elif choice == '6':
                    # EMI
                    principal = self.validator.validate_positive_number(input("Loan amount: "))
                    rate = self.validator.validate_positive_number(input("Annual interest rate (%): "))
                    months = self.validator.validate_positive_number(input("Loan term (months): "))
                    
                    result = self.financial_ops.emi_calculation(principal, rate, months)
                    expression = f"EMI for {principal} at {rate}% for {months} months"
                    self.display.display_result("EMI", expression, result)
                    self.history_manager.add_record("EMI", expression, result, 'financial')
                    self.current_result = result
                
                else:
                    self.display.display_error("Invalid choice")
                
                continue_calc = input("\nPerform another financial calculation? (y/n): ").lower()
                if continue_calc != 'y':
                    break
                    
            except ValueError as e:
                self.display.display_error(str(e))
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.display.display_error(f"Financial calculation error: {e}")
    
    def unit_converter(self):
        """Unit conversion operations"""
        self.display.display_header("UNIT CONVERTER")
        
        print("Available conversions: length, weight, temperature, area, volume, currency, digital")
        print("Enter 'back' to return to main menu")
        
        while True:
            try:
                print(f"\nCurrent result: {self.current_result}")
                print("\n1. Length")
                print("2. Weight")
                print("3. Temperature")
                print("4. Area")
                print("5. Volume")
                print("6. Currency")
                print("7. Digital Storage")
                print("8. Back to Main Menu")
                
                choice = input("\nEnter choice (1-8): ").strip()
                
                if choice == '8' or choice.lower() == 'back':
                    break
                
                value = self.validator.validate_number(input("Enter value to convert: "))
                
                if choice == '1':
                    # Length conversion
                    print("\nLength Conversions:")
                    print("1. Meters to Feet")
                    print("2. Feet to Meters")
                    print("3. Kilometers to Miles")
                    print("4. Miles to Kilometers")
                    print("5. Centimeters to Inches")
                    print("6. Inches to Centimeters")
                    
                    conv_choice = input("Enter conversion choice (1-6): ").strip()
                    
                    if conv_choice == '1':
                        result = self.conversion_ops.meters_to_feet(value)
                        expression = f"{value} meters to feet"
                    elif conv_choice == '2':
                        result = self.conversion_ops.feet_to_meters(value)
                        expression = f"{value} feet to meters"
                    elif conv_choice == '3':
                        result = self.conversion_ops.kilometers_to_miles(value)
                        expression = f"{value} km to miles"
                    elif conv_choice == '4':
                        result = self.conversion_ops.miles_to_kilometers(value)
                        expression = f"{value} miles to km"
                    elif conv_choice == '5':
                        result = self.conversion_ops.centimeters_to_inches(value)
                        expression = f"{value} cm to inches"
                    elif conv_choice == '6':
                        result = self.conversion_ops.inches_to_centimeters(value)
                        expression = f"{value} inches to cm"
                    else:
                        self.display.display_error("Invalid conversion choice")
                        continue
                    
                    self.display.display_result("Length Conversion", expression, result)
                    self.history_manager.add_record("Length Conversion", expression, result, 'conversion')
                    self.current_result = result
                
                elif choice == '2':
                    # Weight conversion
                    print("\nWeight Conversions:")
                    print("1. Kilograms to Pounds")
                    print("2. Pounds to Kilograms")
                    print("3. Grams to Ounces")
                    print("4. Ounces to Grams")
                    
                    conv_choice = input("Enter conversion choice (1-4): ").strip()
                    
                    if conv_choice == '1':
                        result = self.conversion_ops.kilograms_to_pounds(value)
                        expression = f"{value} kg to pounds"
                    elif conv_choice == '2':
                        result = self.conversion_ops.pounds_to_kilograms(value)
                        expression = f"{value} pounds to kg"
                    elif conv_choice == '3':
                        result = self.conversion_ops.grams_to_ounces(value)
                        expression = f"{value} grams to ounces"
                    elif conv_choice == '4':
                        result = self.conversion_ops.ounces_to_grams(value)
                        expression = f"{value} ounces to grams"
                    else:
                        self.display.display_error("Invalid conversion choice")
                        continue
                    
                    self.display.display_result("Weight Conversion", expression, result)
                    self.history_manager.add_record("Weight Conversion", expression, result, 'conversion')
                    self.current_result = result
                
                elif choice == '3':
                    # Temperature conversion
                    print("\nTemperature Conversions:")
                    print("1. Celsius to Fahrenheit")
                    print("2. Fahrenheit to Celsius")
                    print("3. Celsius to Kelvin")
                    print("4. Kelvin to Celsius")
                    print("5. Fahrenheit to Kelvin")
                    print("6. Kelvin to Fahrenheit")
                    
                    conv_choice = input("Enter conversion choice (1-6): ").strip()
                    
                    if conv_choice == '1':
                        result = self.conversion_ops.celsius_to_fahrenheit(value)
                        expression = f"{value}°C to Fahrenheit"
                    elif conv_choice == '2':
                        result = self.conversion_ops.fahrenheit_to_celsius(value)
                        expression = f"{value}°F to Celsius"
                    elif conv_choice == '3':
                        result = self.conversion_ops.celsius_to_kelvin(value)
                        expression = f"{value}°C to Kelvin"
                    elif conv_choice == '4':
                        result = self.conversion_ops.kelvin_to_celsius(value)
                        expression = f"{value}K to Celsius"
                    elif conv_choice == '5':
                        result = self.conversion_ops.fahrenheit_to_kelvin(value)
                        expression = f"{value}°F to Kelvin"
                    elif conv_choice == '6':
                        result = self.conversion_ops.kelvin_to_fahrenheit(value)
                        expression = f"{value}K to Fahrenheit"
                    else:
                        self.display.display_error("Invalid conversion choice")
                        continue
                    
                    self.display.display_result("Temperature Conversion", expression, result)
                    self.history_manager.add_record("Temperature Conversion", expression, result, 'conversion')
                    self.current_result = result
                
                elif choice == '4':
                    # Area conversion
                    print("\nArea Conversions:")
                    print("1. Square Meters to Square Feet")
                    print("2. Square Feet to Square Meters")
                    print("3. Hectares to Acres")
                    print("4. Acres to Hectares")
                    
                    conv_choice = input("Enter conversion choice (1-4): ").strip()
                    
                    if conv_choice == '1':
                        result = self.conversion_ops.square_meters_to_square_feet(value)
                        expression = f"{value} m² to ft²"
                    elif conv_choice == '2':
                        result = self.conversion_ops.square_feet_to_square_meters(value)
                        expression = f"{value} ft² to m²"
                    elif conv_choice == '3':
                        result = self.conversion_ops.hectares_to_acres(value)
                        expression = f"{value} hectares to acres"
                    elif conv_choice == '4':
                        result = self.conversion_ops.acres_to_hectares(value)
                        expression = f"{value} acres to hectares"
                    else:
                        self.display.display_error("Invalid conversion choice")
                        continue
                    
                    self.display.display_result("Area Conversion", expression, result)
                    self.history_manager.add_record("Area Conversion", expression, result, 'conversion')
                    self.current_result = result
                
                elif choice == '5':
                    # Volume conversion
                    print("\nVolume Conversions:")
                    print("1. Liters to Gallons")
                    print("2. Gallons to Liters")
                    print("3. Milliliters to Fluid Ounces")
                    print("4. Fluid Ounces to Milliliters")
                    
                    conv_choice = input("Enter conversion choice (1-4): ").strip()
                    
                    if conv_choice == '1':
                        result = self.conversion_ops.liters_to_gallons(value)
                        expression = f"{value} liters to gallons"
                    elif conv_choice == '2':
                        result = self.conversion_ops.gallons_to_liters(value)
                        expression = f"{value} gallons to liters"
                    elif conv_choice == '3':
                        result = self.conversion_ops.milliliters_to_fluid_ounces(value)
                        expression = f"{value} ml to fl oz"
                    elif conv_choice == '4':
                        result = self.conversion_ops.fluid_ounces_to_milliliters(value)
                        expression = f"{value} fl oz to ml"
                    else:
                        self.display.display_error("Invalid conversion choice")
                        continue
                    
                    self.display.display_result("Volume Conversion", expression, result)
                    self.history_manager.add_record("Volume Conversion", expression, result, 'conversion')
                    self.current_result = result
                
                elif choice == '6':
                    # Currency conversion
                    print("\nCurrency Conversions:")
                    print("1. USD to EUR")
                    print("2. EUR to USD")
                    print("3. USD to GBP")
                    print("4. GBP to USD")
                    print("5. USD to JPY")
                    print("6. JPY to USD")
                    
                    conv_choice = input("Enter conversion choice (1-6): ").strip()
                    
                    if conv_choice == '1':
                        result = self.conversion_ops.usd_to_eur(value)
                        expression = f"{value} USD to EUR"
                    elif conv_choice == '2':
                        result = self.conversion_ops.eur_to_usd(value)
                        expression = f"{value} EUR to USD"
                    elif conv_choice == '3':
                        result = self.conversion_ops.usd_to_gbp(value)
                        expression = f"{value} USD to GBP"
                    elif conv_choice == '4':
                        result = self.conversion_ops.gbp_to_usd(value)
                        expression = f"{value} GBP to USD"
                    elif conv_choice == '5':
                        result = self.conversion_ops.usd_to_jpy(value)
                        expression = f"{value} USD to JPY"
                    elif conv_choice == '6':
                        result = self.conversion_ops.jpy_to_usd(value)
                        expression = f"{value} JPY to USD"
                    else:
                        self.display.display_error("Invalid conversion choice")
                        continue
                    
                    self.display.display_result("Currency Conversion", expression, result)
                    self.history_manager.add_record("Currency Conversion", expression, result, 'conversion')
                    self.current_result = result
                
                elif choice == '7':
                    # Digital storage conversion
                    print("\nDigital Storage Conversions:")
                    print("1. MB to GB")
                    print("2. GB to MB")
                    print("3. GB to TB")
                    print("4. TB to GB")
                    
                    conv_choice = input("Enter conversion choice (1-4): ").strip()
                    
                    if conv_choice == '1':
                        result = self.conversion_ops.megabytes_to_gigabytes(value)
                        expression = f"{value} MB to GB"
                    elif conv_choice == '2':
                        result = self.conversion_ops.gigabytes_to_megabytes(value)
                        expression = f"{value} GB to MB"
                    elif conv_choice == '3':
                        result = self.conversion_ops.gigabytes_to_terabytes(value)
                        expression = f"{value} GB to TB"
                    elif conv_choice == '4':
                        result = self.conversion_ops.terabytes_to_gigabytes(value)
                        expression = f"{value} TB to GB"
                    else:
                        self.display.display_error("Invalid conversion choice")
                        continue
                    
                    self.display.display_result("Digital Storage Conversion", expression, result)
                    self.history_manager.add_record("Digital Storage Conversion", expression, result, 'conversion')
                    self.current_result = result
                
                else:
                    self.display.display_error("Invalid choice")
                
                continue_calc = input("\nPerform another conversion? (y/n): ").lower()
                if continue_calc != 'y':
                    break
                    
            except ValueError as e:
                self.display.display_error(str(e))
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.display.display_error(f"Conversion error: {e}")
    
    def memory_functions(self):
        """Memory management functions"""
        self.display.display_header("MEMORY FUNCTIONS")
        
        while True:
            try:
                self.display.display_memory_status(self.memory_manager)
                
                print("\nMemory Operations:")
                print("1. Memory Clear (MC)")
                print("2. Memory Recall (MR)")
                print("3. Memory Add (M+)")
                print("4. Memory Subtract (M-)")
                print("5. Memory Store (MS)")
                print("6. Recall from Slot")
                print("7. Store in Slot")
                print("8. Clear Slot")
                print("9. Get Constant")
                print("10. Back to Main Menu")
                
                choice = input("\nEnter choice (1-10): ").strip()
                
                if choice == '10':
                    break
                
                elif choice == '1':
                    self.memory_manager.memory_clear()
                    self.display.display_success("Memory cleared")
                
                elif choice == '2':
                    result = self.memory_manager.memory_recall()
                    print(f"Memory value: {result}")
                
                elif choice == '3':
                    value = self.validator.validate_number(input("Enter value to add: "))
                    self.memory_manager.memory_add(value)
                    self.display.display_success(f"Added {value} to memory")
                
                elif choice == '4':
                    value = self.validator.validate_number(input("Enter value to subtract: "))
                    self.memory_manager.memory_subtract(value)
                    self.display.display_success(f"Subtracted {value} from memory")
                
                elif choice == '5':
                    value = self.validator.validate_number(input("Enter value to store: "))
                    self.memory_manager.memory_store(value)
                    self.display.display_success(f"Stored {value} in memory")
                
                elif choice == '6':
                    slot = input("Enter slot name: ").strip() or 'default'
                    result = self.memory_manager.memory_recall_slot(slot)
                    print(f"Value in slot '{slot}': {result}")
                
                elif choice == '7':
                    value = self.validator.validate_number(input("Enter value to store: "))
                    slot = input("Enter slot name: ").strip() or 'default'
                    self.memory_manager.memory_store(value, slot)
                    self.display.display_success(f"Stored {value} in slot '{slot}'")
                
                elif choice == '8':
                    slot = input("Enter slot name to clear: ").strip() or 'default'
                    self.memory_manager.memory_clear_slot(slot)
                    self.display.display_success(f"Cleared slot '{slot}'")
                
                elif choice == '9':
                    constant = input("Enter constant name (pi, e, phi, c, g): ").strip().lower()
                    result = self.memory_manager.get_constant(constant)
                    if result is not None:
                        print(f"{constant} = {result}")
                    else:
                        self.display.display_error("Constant not found")
                
                else:
                    self.display.display_error("Invalid choice")
                
                input("\nPress Enter to continue...")
                    
            except ValueError as e:
                self.display.display_error(str(e))
                input("Press Enter to continue...")
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.display.display_error(f"Memory operation error: {e}")
                input("Press Enter to continue...")
    
    def history_functions(self):
        """History and statistics management"""
        self.display.display_header("HISTORY & STATISTICS")
        
        while True:
            try:
                print("\n1. View Calculation History")
                print("2. Clear History")
                print("3. View Statistics")
                print("4. Export History")
                print("5. Back to Main Menu")
                
                choice = input("\nEnter choice (1-5): ").strip()
                
                if choice == '5':
                    break
                
                elif choice == '1':
                    history = self.history_manager.get_history(limit=20)
                    self.display.display_history(history)
                
                elif choice == '2':
                    confirm = input("Are you sure you want to clear all history? (y/n): ").lower()
                    if confirm == 'y':
                        self.history_manager.clear_history()
                        self.display.display_success("History cleared")
                    else:
                        print("Operation cancelled")
                
                elif choice == '3':
                    stats = self.history_manager.get_statistics()
                    self.display.display_statistics(stats)
                
                elif choice == '4':
                    filename = input("Enter filename (or press Enter for default): ").strip()
                    if not filename:
                        filename = 'calculator_history.txt'
                    success, message = self.history_manager.export_history(filename)
                    if success:
                        self.display.display_success(message)
                    else:
                        self.display.display_error(message)
                
                else:
                    self.display.display_error("Invalid choice")
                
                input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.display.display_error(f"History operation error: {e}")
                input("Press Enter to continue...")
    
    def show_help(self):
        """Display help information"""
        self.display.display_header("HELP")
        self.display.display_help()
        input("\nPress Enter to continue...")

def main():
    """Main application entry point"""
    try:
        calculator = AdvancedCalculator()
        calculator.main_menu()
    except KeyboardInterrupt:
        print("\n\nCalculator session ended. Goodbye!")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        print("Please check your installation and try again.")

if __name__ == "__main__":
    main()
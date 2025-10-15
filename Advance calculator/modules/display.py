import os

class Display:
    """Display and formatting utilities"""
    
    @staticmethod
    def clear_screen():
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def display_header(title):
        """Display a formatted header"""
        Display.clear_screen()
        print("=" * 70)
        print(f"{'ADVANCED CALCULATOR':^70}")
        print("=" * 70)
        print(f"{title:^70}")
        print("-" * 70)
    
    @staticmethod
    def display_result(operation, expression, result):
        """Display calculation result"""
        print(f"\nOperation: {operation}")
        print(f"Expression: {expression}")
        print(f"Result: {result}")
        print("-" * 50)
    
    @staticmethod
    def display_error(error_message):
        """Display error message"""
        print(f"\n❌ Error: {error_message}")
    
    @staticmethod
    def display_success(message):
        """Display success message"""
        print(f"\n✅ {message}")
    
    @staticmethod
    def display_history(history_records):
        """Display calculation history"""
        if not history_records:
            print("No history records found.")
            return
        
        print(f"\n{'Calculation History':^60}")
        print("=" * 60)
        print(f"{'Time':<20} {'Operation':<15} {'Result':<20}")
        print("-" * 60)
        
        for record in history_records[:10]:  # Show last 10 records
            time_str = record['timestamp'][11:19]  # Extract time only
            operation = record['operation'][:14]  # Truncate if too long
            result = str(record['result'])[:18]  # Truncate if too long
            print(f"{time_str:<20} {operation:<15} {result:<20}")
    
    @staticmethod
    def display_memory_status(memory_manager):
        """Display memory status"""
        status = memory_manager.get_memory_status()
        print(f"\n{'Memory Status':^50}")
        print("=" * 50)
        print(f"Main Memory: {status['main_memory']}")
        
        if status['memory_slots']:
            print("\nMemory Slots:")
            for slot, value in status['memory_slots'].items():
                print(f"  {slot}: {value}")
        
        print(f"\nAvailable Constants: {', '.join(status['available_constants'])}")
    
    @staticmethod
    def display_statistics(statistics):
        """Display usage statistics"""
        print(f"\n{'Usage Statistics':^50}")
        print("=" * 50)
        print(f"Total Calculations: {statistics['total_calculations']}")
        print(f"Unique Operations: {statistics['unique_operations']}")
        print(f"First Calculation: {statistics['first_calculation']}")
        print(f"Last Calculation: {statistics['last_calculation']}")
        
        if statistics['category_stats']:
            print("\nOperations by Category:")
            for stat in statistics['category_stats']:
                print(f"  {stat['category']}: {stat['count']}")
    
    @staticmethod
    def display_help():
        """Display help information"""
        print(f"\n{'Calculator Help':^60}")
        print("=" * 60)
        print("Available Operations:")
        print("1. Basic: +, -, *, /, ^, %, !, √")
        print("2. Scientific: sin, cos, tan, log, ln, exp")
        print("3. Financial: interest, loan, roi, npv")
        print("4. Conversions: length, weight, temperature, currency")
        print("5. Memory: MC, MR, M+, M-, MS")
        print("6. History: View and manage calculation history")
        print("\nTips:")
        print("- Use 'pi', 'e' for mathematical constants")
        print("- Enter angles in degrees or radians")
        print("- Use comma-separated values for lists")
        print("- Press Ctrl+C to exit")
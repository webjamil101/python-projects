class MemoryManager:
    """Manage calculator memory functions"""
    
    def __init__(self):
        self.memory = 0
        self.memory_slots = {}  # Multiple memory slots
        self.constants = {
            'pi': 3.141592653589793,
            'e': 2.718281828459045,
            'phi': 1.618033988749895,  # Golden ratio
            'c': 299792458,  # Speed of light (m/s)
            'g': 9.80665,    # Gravity (m/s²)
        }
    
    def memory_clear(self):
        """Clear memory"""
        self.memory = 0
    
    def memory_recall(self):
        """Recall from memory"""
        return self.memory
    
    def memory_add(self, value):
        """Add to memory"""
        self.memory += value
    
    def memory_subtract(self, value):
        """Subtract from memory"""
        self.memory -= value
    
    def memory_store(self, value, slot='default'):
        """Store value in memory slot"""
        self.memory_slots[slot] = value
    
    def memory_recall_slot(self, slot='default'):
        """Recall value from memory slot"""
        return self.memory_slots.get(slot, 0)
    
    def memory_clear_slot(self, slot='default'):
        """Clear specific memory slot"""
        if slot in self.memory_slots:
            del self.memory_slots[slot]
    
    def memory_clear_all_slots(self):
        """Clear all memory slots"""
        self.memory_slots.clear()
    
    def get_constant(self, constant_name):
        """Get mathematical constant"""
        return self.constants.get(constant_name.lower())
    
    def list_constants(self):
        """List all available constants"""
        return list(self.constants.keys())
    
    def list_memory_slots(self):
        """List all memory slots and their values"""
        return self.memory_slots.copy()
    
    def get_memory_status(self):
        """Get memory status"""
        return {
            'main_memory': self.memory,
            'memory_slots': self.memory_slots,
            'available_constants': list(self.constants.keys())
        }
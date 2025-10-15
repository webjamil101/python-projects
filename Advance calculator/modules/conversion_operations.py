class ConversionOperations:
    """Unit conversion operations for length, weight, temperature, etc."""
    
    # Length conversions
    @staticmethod
    def meters_to_feet(meters):
        return meters * 3.28084
    
    @staticmethod
    def feet_to_meters(feet):
        return feet / 3.28084
    
    @staticmethod
    def kilometers_to_miles(km):
        return km * 0.621371
    
    @staticmethod
    def miles_to_kilometers(miles):
        return miles / 0.621371
    
    @staticmethod
    def centimeters_to_inches(cm):
        return cm * 0.393701
    
    @staticmethod
    def inches_to_centimeters(inches):
        return inches / 0.393701
    
    # Weight conversions
    @staticmethod
    def kilograms_to_pounds(kg):
        return kg * 2.20462
    
    @staticmethod
    def pounds_to_kilograms(lbs):
        return lbs / 2.20462
    
    @staticmethod
    def grams_to_ounces(grams):
        return grams * 0.035274
    
    @staticmethod
    def ounces_to_grams(ounces):
        return ounces / 0.035274
    
    # Temperature conversions
    @staticmethod
    def celsius_to_fahrenheit(celsius):
        return (celsius * 9/5) + 32
    
    @staticmethod
    def fahrenheit_to_celsius(fahrenheit):
        return (fahrenheit - 32) * 5/9
    
    @staticmethod
    def celsius_to_kelvin(celsius):
        return celsius + 273.15
    
    @staticmethod
    def kelvin_to_celsius(kelvin):
        return kelvin - 273.15
    
    @staticmethod
    def fahrenheit_to_kelvin(fahrenheit):
        return (fahrenheit - 32) * 5/9 + 273.15
    
    @staticmethod
    def kelvin_to_fahrenheit(kelvin):
        return (kelvin - 273.15) * 9/5 + 32
    
    # Area conversions
    @staticmethod
    def square_meters_to_square_feet(sq_m):
        return sq_m * 10.7639
    
    @staticmethod
    def square_feet_to_square_meters(sq_ft):
        return sq_ft / 10.7639
    
    @staticmethod
    def hectares_to_acres(hectares):
        return hectares * 2.47105
    
    @staticmethod
    def acres_to_hectares(acres):
        return acres / 2.47105
    
    # Volume conversions
    @staticmethod
    def liters_to_gallons(liters):
        return liters * 0.264172
    
    @staticmethod
    def gallons_to_liters(gallons):
        return gallons / 0.264172
    
    @staticmethod
    def milliliters_to_fluid_ounces(ml):
        return ml * 0.033814
    
    @staticmethod
    def fluid_ounces_to_milliliters(fl_oz):
        return fl_oz / 0.033814
    
    # Speed conversions
    @staticmethod
    def kmh_to_mph(kmh):
        return kmh * 0.621371
    
    @staticmethod
    def mph_to_kmh(mph):
        return mph / 0.621371
    
    @staticmethod
    def meters_per_second_to_kmh(mps):
        return mps * 3.6
    
    @staticmethod
    def kmh_to_meters_per_second(kmh):
        return kmh / 3.6
    
    # Digital storage conversions
    @staticmethod
    def megabytes_to_gigabytes(mb):
        return mb / 1024
    
    @staticmethod
    def gigabytes_to_megabytes(gb):
        return gb * 1024
    
    @staticmethod
    def gigabytes_to_terabytes(gb):
        return gb / 1024
    
    @staticmethod
    def terabytes_to_gigabytes(tb):
        return tb * 1024
    
    # Currency conversions (using fixed rates for demonstration)
    @staticmethod
    def usd_to_eur(usd):
        return usd * 0.85  # Example rate
    
    @staticmethod
    def eur_to_usd(eur):
        return eur / 0.85
    
    @staticmethod
    def usd_to_gbp(usd):
        return usd * 0.73  # Example rate
    
    @staticmethod
    def gbp_to_usd(gbp):
        return gbp / 0.73
    
    @staticmethod
    def usd_to_jpy(usd):
        return usd * 110.0  # Example rate
    
    @staticmethod
    def jpy_to_usd(jpy):
        return jpy / 110.0
    
    # Time conversions
    @staticmethod
    def hours_to_minutes(hours):
        return hours * 60
    
    @staticmethod
    def minutes_to_hours(minutes):
        return minutes / 60
    
    @staticmethod
    def days_to_hours(days):
        return days * 24
    
    @staticmethod
    def hours_to_days(hours):
        return hours / 24
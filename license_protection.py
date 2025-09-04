# license_protection.py
import os
import sys
import hashlib
import json
from datetime import datetime

def add_license_protection(file_path):
    with open(file_path, 'r') as f:
        code = f.read()
    
    # Create license check function
    license_check = '''
def _check_license():
    # Watermark and license check
    _watermark = "Sidetalk by Golam Mahadi Rafi"
    _license_hash = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    
    # Check if running in authorized environment
    try:
        import os
        if not os.path.exists('.license'):
            print("ERROR: License file not found. This software is licensed to Golam Mahadi Rafi.")
            sys.exit(1)
        
        with open('.license', 'r') as f:
            license_data = f.read().strip()
        
        if hashlib.sha256(license_data.encode()).hexdigest() != _license_hash:
            print("ERROR: Invalid license. This software is licensed to Golam Mahadi Rafi.")
            sys.exit(1)
    except:
        print("ERROR: License verification failed. This software is licensed to Golam Mahadi Rafi.")
        sys.exit(1)

# Execute license check
_check_license()
'''
    
    # Add license check at the beginning of the file
    protected_code = license_check + '\n\n' + code
    
    # Save protected code
    protected_path = file_path.replace('.py', '_protected.py')
    with open(protected_path, 'w') as f:
        f.write(protected_code)
    
    print(f"Protected code saved to: {protected_path}")
    return protected_path

# Add protection to both files
add_license_protection('server.py')
add_license_protection('client.py')

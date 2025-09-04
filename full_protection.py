# full_protection.py
import os
import subprocess
import shutil

def apply_all_protections():
    print("Applying all protections to Sidetalk code...")
    
    # Step 1: Create backup
    if not os.path.exists('backup'):
        os.makedirs('backup')
    
    shutil.copy('server.py', 'backup/server.py')
    shutil.copy('client.py', 'backup/client.py')
    print("✓ Created backup")
    
    # Step 2: Minify code
    print("Minifying code...")
    os.system('python minify_code.py')
    
    # Step 3: Encode strings
    print("Encoding strings...")
    os.system('python encode_strings.py')
    
    # Step 4: Add license protection
    print("Adding license protection...")
    os.system('python license_protection.py')
    
    # Step 5: Add anti-debugging
    print("Adding anti-debugging measures...")
    os.system('python anti_debug.py')
    
    # Step 6: Obfuscate with PyArmor
    print("Obfuscating with PyArmor...")
    subprocess.run(['pyarmor', 'obfuscate', 'server.py', '--output', 'server_obfuscated.py', '--restrict-mode', '2'])
    subprocess.run(['pyarmor', 'obfuscate', 'client.py', '--output', 'client_obfuscated.py', '--restrict-mode', '2'])
    
    # Step 7: Create license file
    print("Creating license file...")
    os.system('python create_license.py')
    
    # Step 8: Package as executable
    print("Packaging as executable...")
    os.system('pyinstaller sidetalk.spec')
    
    print("✓ All protections applied successfully!")
    print("Protected files:")
    print("- server_obfuscated.py")
    print("- client_obfuscated.py")
    print("- dist/SidetalkServer")
    print("- dist/SidetalkClient")

if __name__ == "__main__":
    apply_all_protections()

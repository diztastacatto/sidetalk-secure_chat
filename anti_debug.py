# anti_debug.py
import sys
import os
import inspect
import traceback

def add_anti_debug(file_path):
    with open(file_path, 'r') as f:
        code = f.read()
    
    # Create anti-debugging code
    anti_debug = '''
def _anti_debug():
    # Check if running in a debugger
    try:
        import sys
        import os
        import inspect
        
        # Check for debugger
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            print("ERROR: Debugger detected. This software is licensed to Golam Mahadi Rafi.")
            sys.exit(1)
        
        # Check for common debugging tools
        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] in ['gdb', 'lldb', 'strace', 'ltrace']:
                    print("ERROR: Debugging tool detected. This software is licensed to Golam Mahadi Rafi.")
                    sys.exit(1)
        except:
            pass
        
        # Check for modified files
        current_file = inspect.currentframe().f_code.co_filename
        if os.path.exists(current_file):
            with open(current_file, 'r') as f:
                file_content = f.read()
                if "Golam Mahadi Rafi" not in file_content:
                    print("ERROR: Modified file detected. This software is licensed to Golam Mahadi Rafi.")
                    sys.exit(1)
    except:
        pass

# Execute anti-debug check
_anti_debug()
'''
    
    # Add anti-debugging code
    protected_code = anti_debug + '\n\n' + code
    
    # Save protected code
    protected_path = file_path.replace('.py', '_antidebug.py')
    with open(protected_path, 'w') as f:
        f.write(protected_code)
    
    print(f"Anti-debug code added to: {protected_path}")
    return protected_code

# Add anti-debugging to both files
add_anti_debug('server.py')
add_anti_debug('client.py')

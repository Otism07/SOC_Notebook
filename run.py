#!/usr/bin/env python3

import os
import sys
import subprocess

def get_resource_path(relative_path):
    # Get absolute path to resource, works for both development and PyInstaller bundles
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        # Running in development mode
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

def run_application():
    # Launch the SOC Case Logger application
    
    # Determine execution environment and launch accordingly
    if getattr(sys, 'frozen', False):
        # Running as bundled executable (PyInstaller)
        script_dir = os.path.dirname(sys.executable)
        
        try:
            # Configure module path for bundled imports
            src_path = get_resource_path('src')
            if src_path not in sys.path:
                sys.path.insert(0, src_path)
            
            # Import and run the main application directly
            from src.main import main as app_main
            
            print("Starting SOC Case Logger (bundled version)...")
            return app_main()
            
        except ImportError as e:
            print(f"Error importing application modules: {e}")
            print("Please ensure all dependencies are included in the bundle.")
            return 1
        except Exception as e:
            print(f"Error starting bundled application: {e}")
            return 1
    else:
        # Running as development script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        main_app_path = os.path.join(script_dir, 'src', 'main.py')
        
        # Validate that the main application file exists
        if not os.path.exists(main_app_path):
            print("Error: Could not find main.py in the src directory")
            print(f"Expected location: {main_app_path}")
            print("Please ensure you're running from the project root directory.")
            return 1
        
        # Configure working directory for proper module resolution
        src_dir = os.path.join(script_dir, 'src')
        
        try:
            print("Starting SOC Case Logger (development mode)...")
            print(f"Working directory: {src_dir}")
            
            # Launch the application as a subprocess
            result = subprocess.run([sys.executable, 'main.py'], 
                                  cwd=src_dir,
                                  check=False)
            
            return result.returncode
            
        except KeyboardInterrupt:
            print("\nApplication interrupted by user")
            return 0
        except Exception as e:
            print(f"Error starting development application: {e}")
            return 1

if __name__ == "__main__":
    # Execute the launcher and exit with appropriate code
    exit_code = run_application()
    sys.exit(exit_code)
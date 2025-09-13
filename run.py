#!/usr/bin/env python3
"""
SOC Case Logger Launcher Script

This script provides an easy way to launch the SOC Case Logger application
from the project root directory or as a bundled executable.
"""

import os
import sys
import subprocess

def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

def main():
    """Launch the SOC Case Logger application"""
    
    # Determine if we're running as bundled executable or as script
    if getattr(sys, 'frozen', False):
        # Running as bundled executable
        script_dir = os.path.dirname(sys.executable)
        
        # Import and run directly
        try:
            # Add src to path for imports
            src_path = get_resource_path('src')
            if src_path not in sys.path:
                sys.path.insert(0, src_path)
            
            # Import main application
            from src.main import main as app_main
            
            print("Starting SOC Case Logger...")
            return app_main()
            
        except ImportError as e:
            print(f"Error importing application: {e}")
            return 1
        except Exception as e:
            print(f"Error starting application: {e}")
            return 1
    else:
        # Running as script - use original method
        script_dir = os.path.dirname(os.path.abspath(__file__))
        main_app_path = os.path.join(script_dir, 'src', 'main.py')
        
        # Check if the main application exists
        if not os.path.exists(main_app_path):
            print("Error: Could not find main.py in the src directory")
            print(f"Expected location: {main_app_path}")
            return 1
        
        # Change to the src directory and run the application
        src_dir = os.path.join(script_dir, 'src')
        
        try:
            print("Starting SOC Case Logger...")
            print(f"Working directory: {src_dir}")
            
            # Run the application
            result = subprocess.run([sys.executable, 'main.py'], 
                                  cwd=src_dir,
                                  check=False)
            
            return result.returncode
            
        except KeyboardInterrupt:
            print("\nApplication interrupted by user")
            return 0
        except Exception as e:
            print(f"Error starting application: {e}")
            return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

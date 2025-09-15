#!/usr/bin/env python3

# Standard library imports
import os
import sys
import tkinter as tk
from tkinter import messagebox
import logging
import traceback
import threading
from datetime import datetime

# Add the src directory to the Python path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the main GUI window
from gui.main_window import SOCCaseLogger

def setup_logging():
    # Set up comprehensive application logging with file and console output
    
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    # Configure logging with both file and console output
    log_file = os.path.join(logs_dir, 'app.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("SOC Case Logger application started")
    return logger

class ApplicationRecovery:
    # Handles application crashes and provides emergency data recovery
    # Implements global exception handling and automatic backup functionality
    
    def __init__(self, logger):
        # Initialize recovery system with logging support
        self.logger = logger
        self.app_instance = None
        self.setup_exception_handler()
    
    def setup_exception_handler(self):
        # Set up global exception handler to catch unhandled exceptions
        def exception_handler(exc_type, exc_value, exc_traceback):
            # Don't handle KeyboardInterrupt (Ctrl+C)
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            
            # Log the full exception details
            error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            self.logger.critical(f"Unhandled exception: {error_msg}")
            
            # Try to save current work before crashing
            self.emergency_save()
            
            # Show user-friendly error dialog
            try:
                root = tk.Tk()
                root.withdraw()  # Hide the root window
                messagebox.showerror(
                    "Application Error", 
                    "An unexpected error occurred. The application will close.\n"
                    "Your current work has been saved to emergency backup.\n\n"
                    "Please check the log file for details and restart the application."
                )
                root.destroy()
            except:
                # If GUI fails, fall back to console output
                print("Critical error: Unable to display error dialog")
                print(error_msg)
        
        # Install the custom exception handler
        sys.excepthook = exception_handler
    
    def set_app_instance(self, app):
        # Set the application instance for emergency save functionality
        self.app_instance = app
    
    def emergency_save(self):
        # Perform emergency save of current work in case of application crash
        try:
            if self.app_instance and hasattr(self.app_instance, 'emergency_save'):
                # Use the application's built-in emergency save if available
                self.app_instance.emergency_save()
                self.logger.info("Emergency save completed")
            else:
                # Create a basic emergency save file
                emergency_file = os.path.join(
                    os.path.dirname(os.path.dirname(__file__)), 
                    'data', 
                    f'emergency_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                )
                
                emergency_data = {
                    'timestamp': datetime.now().isoformat(),
                    'message': 'Emergency backup created due to application crash',
                    'recovery_instructions': 'Restart the application and check recent cases'
                }
                
                # Ensure data directory exists
                os.makedirs(os.path.dirname(emergency_file), exist_ok=True)
                with open(emergency_file, 'w') as f:
                    import json
                    json.dump(emergency_data, f, indent=2)
                
                self.logger.info(f"Emergency backup created: {emergency_file}")
        except Exception as e:
            self.logger.error(f"Emergency save failed: {e}")
            # Don't let save failure cause another crash

def check_dependencies():
    # Verify that all required dependencies are available
    try:
        # Check for required standard library modules
        import tkinter
        import json
        import os
        from datetime import datetime
        
        # Check for third-party dependencies
        import requests
        from cryptography.fernet import Fernet
        
        return True
    except ImportError as e:
        messagebox.showerror("Missing Dependencies", 
                           f"Required dependency not found: {e}\n"
                           "Please ensure all required packages are installed.\n\n"
                           "Install with: pip install -r requirements.txt")
        return False

def main():
    # Main application entry point
    try:
        # Set up comprehensive logging
        logger = setup_logging()
        
        # Set up crash recovery system
        recovery = ApplicationRecovery(logger)
        
        # Check that all dependencies are available
        if not check_dependencies():
            return 1
        
        # Create the main tkinter window
        root = tk.Tk()
        
        # Set window icon if available
        try:
            icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'icon.ico')
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        except:
            pass  # Icon not found, continue without it
        
        # Configure modern application styling
        try:
            # Use modern theme if available
            style = tk.ttk.Style()
            available_themes = style.theme_names()
            
            # Prefer modern themes based on platform
            preferred_themes = ['vista', 'xpnative', 'winnative', 'clam']
            for theme in preferred_themes:
                if theme in available_themes:
                    style.theme_use(theme)
                    break
            
            # Configure custom button styles for different actions
            style.configure('Accent.TButton', foreground='white', background='#0078d4')
            style.configure('Success.TButton', foreground='white', background='#107c10')
            style.configure('Urgent.TButton', foreground='white', background='#d13438')
            
        except Exception as e:
            logger.warning(f"Could not configure theme: {e}")
        
        # Create and initialize the main application
        logger.info("Initializing SOC Case Logger GUI")
        app = SOCCaseLogger(root)
        
        # Set up recovery for the app instance
        recovery.set_app_instance(app)
        
        # Configure graceful window close behavior
        def on_closing():
            try:
                if messagebox.askokcancel("Quit", "Do you want to quit the SOC Case Logger?"):
                    # Attempt to save current work before closing
                    if hasattr(app, 'save_current_work'):
                        app.save_current_work()
                    logger.info("SOC Case Logger application closed by user")
                    root.destroy()
            except Exception as e:
                logger.error(f"Error during application shutdown: {e}")
                root.destroy()  # Force close if there's an error
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start the main GUI event loop with exception handling
        logger.info("Starting main application loop")
        try:
            root.mainloop()
        except Exception as e:
            logger.critical(f"Main loop crashed: {e}")
            recovery.emergency_save()
            raise
        
        logger.info("SOC Case Logger application ended normally")
        return 0
        
    except Exception as e:
        error_msg = f"Fatal error starting SOC Case Logger: {e}"
        print(error_msg)
        
        # Try to show error in GUI if possible
        try:
            root = tk.Tk()
            root.withdraw()  # Hide the root window
            messagebox.showerror("Fatal Error", error_msg)
        except:
            pass  # GUI not available, error already printed
        
        return 1

if __name__ == "__main__":
    # Start the application and exit with appropriate code
    exit_code = main()
    sys.exit(exit_code)
#!/usr/bin/env python3
import os
import sys
import tkinter as tk
from tkinter import messagebox
import logging
import traceback
import threading
from datetime import datetime

# Add the src directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the main GUI window
from gui.main_window import SOCCaseLogger

def setup_logging():
    """Set up application logging"""
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    # Configure logging
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
    """Handle application crashes and recovery"""
    
    def __init__(self, logger):
        self.logger = logger
        self.app_instance = None
        self.setup_exception_handler()
    
    def setup_exception_handler(self):
        """Set up global exception handler"""
        def exception_handler(exc_type, exc_value, exc_traceback):
            # Don't handle KeyboardInterrupt
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            
            error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            self.logger.critical(f"Unhandled exception: {error_msg}")
            
            # Try to save current work
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
                print("Critical error: Unable to display error dialog")
                print(error_msg)
        
        sys.excepthook = exception_handler
    
    def set_app_instance(self, app):
        """Set the application instance for emergency save"""
        self.app_instance = app
    
    def emergency_save(self):
        """Save current work in case of crash"""
        try:
            if self.app_instance and hasattr(self.app_instance, 'emergency_save'):
                self.app_instance.emergency_save()
                self.logger.info("Emergency save completed")
            else:
                # Create a basic emergency save
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
                
                os.makedirs(os.path.dirname(emergency_file), exist_ok=True)
                with open(emergency_file, 'w') as f:
                    import json
                    json.dump(emergency_data, f, indent=2)
                
                self.logger.info(f"Emergency backup created: {emergency_file}")
        except Exception as e:
            self.logger.error(f"Emergency save failed: {e}")
            # Don't let save failure cause another crash

def check_dependencies():
    """Check if all required dependencies are available"""
    try:
        import tkinter
        import json
        import os
        from datetime import datetime
        return True
    except ImportError as e:
        messagebox.showerror("Missing Dependencies", 
                           f"Required dependency not found: {e}\n"
                           "Please ensure all required packages are installed.")
        return False

def main():
    """Main application entry point"""
    try:
        # Set up logging
        logger = setup_logging()
        
        # Set up crash recovery
        recovery = ApplicationRecovery(logger)
        
        # Check dependencies
        if not check_dependencies():
            return 1
        
        # Create the main tkinter window
        root = tk.Tk()
        
        # Set window icon (if available)
        try:
            # You can add an icon file here if needed
            # root.iconbitmap('path/to/icon.ico')
            pass
        except:
            pass  # Icon not found, continue without it
        
        # Configure the application style
        try:
            # Try to use a modern theme if available
            style = tk.ttk.Style()
            available_themes = style.theme_names()
            
            # Prefer modern themes
            preferred_themes = ['vista', 'xpnative', 'winnative', 'clam']
            for theme in preferred_themes:
                if theme in available_themes:
                    style.theme_use(theme)
                    break
            
            # Configure custom button styles
            style.configure('Accent.TButton', foreground='white', background='#0078d4')
            style.configure('Success.TButton', foreground='white', background='#107c10')
            style.configure('Urgent.TButton', foreground='white', background='#d13438')
            
        except Exception as e:
            logger.warning(f"Could not configure theme: {e}")
        
        # Create and run the application
        logger.info("Initializing SOC Case Logger GUI")
        app = SOCCaseLogger(root)
        
        # Set up recovery for the app instance
        recovery.set_app_instance(app)
        
        # Configure window close behavior
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
        
        # Start the main event loop with exception handling
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
    exit_code = main()
    sys.exit(exit_code)
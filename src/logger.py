import os
from datetime import datetime

class Logger:
    # Basic file logger for application events and error tracking
    # Writes timestamped log entries to a specified file
    
    def __init__(self, log_file='logs/app.log'):
        # Initialize the logger with a specified log file
        self.log_file = log_file
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def log_info(self, message):
        # Log an informational message
        self._log('INFO', message)

    def log_error(self, message):
        # Log an error message
        self._log('ERROR', message)

    def _log(self, level, message):
        # Internal method to write log entries with timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f'[{timestamp}] {level}: {message}\n')
        except Exception as e:
            # Fallback to console if file logging fails
            print(f'[{timestamp}] LOGGING_ERROR: Could not write to log file: {e}')
            print(f'[{timestamp}] {level}: {message}')
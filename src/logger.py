class Logger:
    def __init__(self, log_file='logs/app.log'):
        self.log_file = log_file

    def log_info(self, message):
        self._log('INFO', message)

    def log_error(self, message):
        self._log('ERROR', message)

    def _log(self, level, message):
        with open(self.log_file, 'a') as f:
            f.write(f'{level}: {message}\n')
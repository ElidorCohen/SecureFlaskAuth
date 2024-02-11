import logging
from flask_app import create_app

# Configure the root logger for the application.
# This sets up logging to output both to a file ('application.log') and to stdout,
# with a log level of INFO. It will log timestamps, log level, logger name, and the log message.
# The logger is a critical tool for monitoring and debugging the application.
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s : %(message)s',
                    handlers=[
                        logging.FileHandler("../application.log"),  # Writes logs to an external file
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    logger.info('Starting the Flask application...')
    app = create_app()
    app.run(host="0.0.0.0")
    logger.info('Flask application has stopped.')

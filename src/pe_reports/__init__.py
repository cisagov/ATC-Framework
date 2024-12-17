"""The pe_reports library."""

import logging
from logging.handlers import RotatingFileHandler

CENTRAL_LOGGING_FILE = "pe_reports_logging.log"
DEBUG = False

# Setup Rotating Logging
"""Set up logging and call the run_pe_script function."""
if DEBUG is True:
    level = "DEBUG"
else:
    level = "INFO"
# Logging will rotate at 2GB
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=level,
    handlers=[
        RotatingFileHandler(CENTRAL_LOGGING_FILE, maxBytes=2000000, backupCount=10)
    ],
)

import os
import sys

from loguru import logger

# Remove default sink (stdout)
logger.remove()

# log_level = "TRACE" # (5)
# log_level = "DEBUG" # (10)
log_level = "INFO"  # (20)
# log_level = "SUCCESS" # (25)
# log_level = "WARNING"  # (30)
# log_level = "ERROR" # (40)
# log_level = "CRITICAL" # (50)

log_default = os.environ.get("LOG_LEVEL", log_level).upper()

# Add a new sink with a custom logger level (e.g., WARNING)
logger.add(sink=sys.stdout, level=log_default)

#!/usr/bin/env python3
import os
import logging
from core.database import init_database
from core.config import config
from web import create_app

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)

app = create_app()

if __name__ == '__main__':
    # Ensure database exists
    init_database()
    logging.info(f"CCAF Server starting on {config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)

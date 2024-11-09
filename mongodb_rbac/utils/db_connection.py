from pymongo import MongoClient
from config.db_config import MONGODB_URI, DATABASE_NAME
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseConnection:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
            try:
                cls._instance.client = MongoClient(MONGODB_URI)
                cls._instance.db = cls._instance.client[DATABASE_NAME]
                logger.info(f"Connected to MongoDB database: {DATABASE_NAME}")
            except Exception as e:
                logger.error(f"Failed to connect to MongoDB: {e}")
                raise
        return cls._instance

    def get_database(self):
        return self.db

    def close_connection(self):
        if hasattr(self, 'client'):
            self.client.close()
            logger.info("MongoDB connection closed")
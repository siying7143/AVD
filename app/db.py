import pymysql
from app.config import DB_CONFIG


def get_connection():
    # Create a fresh MySQL connection for each pipeline or web repository action.
    # Callers own the connection lifecycle and must close it in a finally block.
    return pymysql.connect(**DB_CONFIG)

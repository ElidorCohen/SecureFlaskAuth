import mysql.connector
from mysql.connector import pooling
import bcrypt
import logging

logger = logging.getLogger(__name__)


class Database:
    """
        Database configuration for managing MySQL connection pooling.

        This class initializes a connection pool for efficient database access and provides
        a method to retrieve connections from the pool for executing database operations.

        :param database_config: Configuration dictionary containing database connection parameters.
    """
    def __init__(self, database_config):
        """
            Initializes the database connection pool with the provided configuration.

            :param database_config: A dictionary with database connection settings such as
                                    database name, user, password, host, and port.
        """
        logger.info('Initializing database pool...')
        self.pool = pooling.MySQLConnectionPool(pool_name="mypool",
                                                pool_size=5,
                                                **database_config)

    def get_connection(self):
        """
            Retrieves a connection from the pool.

            :return: A MySQLConnection object from the connection pool for executing database operations.
        """
        logger.info('Getting a new database connection...')
        return self.pool.get_connection()

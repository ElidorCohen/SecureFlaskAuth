import mysql.connector
import bcrypt
import datetime


class User:
    def __init__(self, username, hashed_password=None):
        """
            Initializes a new User object with a username and an optional hashed password.
            :param:
                username (str): The user's username.
                hashed_password (str, optional): The bcrypt hashed password of the user.
        """
        self.username = username
        self.hashed_password = hashed_password

    @staticmethod
    def hash_password(password):
        """
            Hashes a plaintext password using bcrypt.
            :param:
                password (str): The plaintext password to hash.
            :return:
                bytes: The bcrypt hashed password.
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    @staticmethod
    def verify_password(hashed_password, password):
        """
            Verifies a plaintext password against a hashed password.
            :param:
                hashed_password (str): The hashed password.
                password (str): The plaintext password to verify.
            :return:
                bool: True if passwords match, False otherwise.
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    @classmethod
    def create_user(cls, database, username, password, phone_number):
        """
            Creates a new user in the database with a hashed password.
            :param:
                database: The database connection object.
                username (str): The user's username.
                password (str): The user's plaintext password.
            :return:
                str: 'success' if user creation was successful, 'exists' if username is already taken,
                     'failed' if an error occurred during user creation.
        """
        conn = database.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM appusers WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return 'exists'

        hashed_password = cls.hash_password(password)
        try:
            cursor.execute("INSERT INTO appusers (username, hashed_password, phone_number) VALUES (%s, %s, %s)",
                           (username, hashed_password.decode('utf-8'), phone_number))
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            conn.rollback()
            cursor.close()
            conn.close()
            return 'failed'
        else:
            cursor.close()
            conn.close()
            return 'success'

    @classmethod
    def find_by_username(cls, database, username):
        """
            Finds a user by their username.
            :param:
                database: The database connection object.
                username (str): The username to search for.
            :return:
                User or None: A User object if found, None otherwise.
        """
        conn = database.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM appusers WHERE username = %s", (username,))
            user_record = cursor.fetchone()
            if user_record:
                return cls(user_record['username'], user_record['hashed_password'])
            else:
                return None
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return None
        finally:
            cursor.close()
            conn.close()






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

    @classmethod
    def update_user_document(cls, database, username, session_id, otp, otp_expiration):
        """
        Updates the user's document in the database with MFA-related fields.

        :param database: The database connection object.
        :param username: The username of the user to update.
        :param session_id: The generated session ID for MFA.
        :param otp: The generated One-Time Password.
        :param otp_expiration: The expiration time of the OTP.
        """
        conn = database.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE appusers 
                SET session_id = %s, otp = %s, otp_expiration_time = %s 
                WHERE username = %s
            """, (session_id, otp, otp_expiration, username))
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Error updating user document: {err}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    @classmethod
    def get_phone_number(cls, database, username):
        """
        Retrieves the phone number of the user by username.

        :param database: The database connection object.
        :param username: The username to search for.
        :return: The phone number of the user if found, None otherwise.
        """
        conn = database.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT phone_number FROM appusers WHERE username = %s", (username,))
            user_record = cursor.fetchone()
            if user_record:
                return user_record['phone_number']
            else:
                return None
        except mysql.connector.Error as err:
            print(f"Error fetching user's phone number: {err}")
            return None
        finally:
            cursor.close()
            conn.close()

    @classmethod
    def get_user_by_session_id(cls, database, session_id):
        """
        Retrieves user information by session ID.

        :param database: The database connection object.
        :param session_id: The session ID to search for.
        :return: A dictionary of user information if found, None otherwise.
        """
        conn = database.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM appusers WHERE session_id = %s", (session_id,))
            user_record = cursor.fetchone()
            return user_record
        except mysql.connector.Error as err:
            print(f"Error fetching user by session ID: {err}")
            return None
        finally:
            cursor.close()
            conn.close()

    @classmethod
    def clear_mfa_fields(cls, database, username):
        """
        Clears MFA-related fields for a user identified by username, setting the
        'session_id' and 'otp' fields to an empty string and expiring 'otp_expiration_time'
        by setting it to the current timestamp.

        :param database: The database connection object.
        :param username: The username of the user whose MFA fields are to be cleared.
        """
        conn = database.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE appusers 
                SET session_id = '', otp = '', otp_expiration_time = NOW()
                WHERE username = %s
            """, (username,))
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Error clearing MFA fields for user {username}: {err}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()




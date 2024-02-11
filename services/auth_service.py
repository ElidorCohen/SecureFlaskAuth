from SecureFlaskAuth.db import Database
from SecureFlaskAuth.models.user import User
from config import Config
import jwt
import datetime
from flask import request


class AuthenticationService:
    @staticmethod
    def register_user(username, password, phone_number):
        """
            Registers a new user with the given username and password.
            :param:
                username (str): The username of the new user.
                password (str): The plaintext password of the new user.
            :return:
                str: The result of the user creation process ('success', 'exists', or 'failed').
        """
        database = Database(Config.DATABASE_CONFIG)
        result = User.create_user(database, username, password, phone_number)
        return result

    @staticmethod
    def authenticate_user(username, password):
        """
            Authenticates a user based on username and password.
            :param:
                username (str): The username of the user attempting to authenticate.
                password (str): The plaintext password of the user attempting to authenticate.
            :return:
                bool: True if authentication is successful, False otherwise.
        """
        database = Database(Config.DATABASE_CONFIG)
        user = User.find_by_username(database, username)
        if user and User.verify_password(user.hashed_password, password):
            return True
        return False

    @staticmethod
    def create_jwt_token(username):
        """
            Generates a JWT token for the user with a specified expiration time.
            The JWT token is encoded with the user's username and an expiration timestamp.
            :param:
                username (str): The username for which to create the JWT token.
            :return:
                str: A JWT token encoded with the user's username and expiration timestamp.
        """
        exp_time = datetime.datetime.now() + datetime.timedelta(minutes=5)
        exp_timestamp = exp_time.timestamp()
        encoded_jwt = jwt.encode({'username': username,'exp': exp_timestamp}, Config.jwt_config, algorithm='HS256')
        return encoded_jwt

def token_required(f):
    """
        A decorator to enforce JWT token authentication on protected routes.
        :param:
            f (function): The Flask route function to decorate.
        :return:
            function: The decorated route function with JWT authentication enforced.
        """
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Token is missing!'}, 403
        try:
            scheme, token = token.split()
        except ValueError:
            return {'message': 'Token format is invalid!'}, 401
        try:
            data = jwt.decode(token, Config.jwt_config, algorithms=["HS256"])
            print(f"Decoded token data: {data}")
        except jwt.ExpiredSignatureError:
            return {'message': 'Token has expired!'}, 401
        except jwt.InvalidTokenError:
            return {'message': 'Token is invalid!'}, 401
        return f(*args, **kwargs)

    return decorated





import re
from config import Config
from SecureFlaskAuth.db import Database
from flask import request
from flask_restx import Namespace, Resource, fields
from SecureFlaskAuth.extensions import limiter
from SecureFlaskAuth.models.user import User
from SecureFlaskAuth.services.MFA_service import MFAService
from SecureFlaskAuth.services.auth_service import AuthenticationService, token_required
import datetime

api = Namespace('auth', description='Authentication services')

login_model = api.model('LoginModel', {
    'username': fields.String(required=True, description='The username'),
    'password': fields.String(required=True, description='The password'),
})

register_model = api.model('RegisterModel', {
    'username': fields.String(required=True, description='The username'),
    'password': fields.String(required=True, description='The password'),
    'phone_number': fields.String(required=True, description='The phone number'),
})

verify_otp_model = api.model('VerifyOtpModel', {
    'session_id': fields.String(required=True, description='The session ID provided after the initial login.'),
    'otp': fields.String(required=True, description='The OTP sent to the users phone.'),
})



@api.route('/register')
class Register(Resource):
    """
        A resource for user registration.
        :param:
            None directly; uses request data for username and password.
        :return:
            JSON response indicating registration outcome with status code.
    """
    @limiter.limit("10 per hour")
    @api.expect(register_model)
    @api.doc(responses={201: 'User registered successfully.'})
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        phone_number = data.get('phone_number')

        if not validate_phone_number(phone_number):
            return {"message": "Invalid phone number."}, 400

        error_message, status_code = validate_user_input(username, password, check_length=True)
        if error_message:
            return {"message": error_message}, status_code

        result = AuthenticationService.register_user(username, password, phone_number)

        if result == 'success':

            return {"message": "User registered successfully."}, 201
        elif result == 'exists':
            return {"message": "User already exists."}, 409   # duplicate resource
        else:  # result == 'failed'
            return {"message": "Registration failed."}, 200


@api.route('/login')
class Login(Resource):
    """
        A resource for user login.
        :param:
            None directly; uses request data for username and password.
        :return:
            JSON response with JWT token if login is successful, or an error message with status code.
    """
    @limiter.limit("10 per hour")
    @api.expect(login_model)
    @api.doc(responses={200: 'Login successful.', 401: 'Invalid username or password.'})
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        error_message, status_code = validate_user_input(username, password)
        if error_message:
            return {"message": error_message}, status_code

        if AuthenticationService.authenticate_user(username, password):

            # generate a session id
            session_id = MFAService.generate_session_id()
            # generate an OTP
            otp = MFAService.generate_otp()
            # generate the otp_expiration object
            otp_expiration = datetime.datetime.now() + datetime.timedelta(minutes=2)
            # update the user document in the database with the session id, OTP, and OTP expiration
            database = Database(Config.DATABASE_CONFIG)
            User.update_user_document(database, username, session_id, otp, otp_expiration)
            # Get the username's phone number from the database
            phone_number = User.get_phone_number(database, username)
            # send the OTP to the user's phone number
            if phone_number:
                try:
                    MFAService.send_sms_otp(phone_number, otp)
                except Exception as e:
                    print(f"Error: {e}")
                    return {"message": "Failed to send OTP via SMS."}, 500
            return {"message": "Login successful. Use /verify-otp to be fully-authenticated.", "session-ID": session_id}, 200
        else:
            return {"message": "Invalid username or password."}, 401


@api.route('/private')
class Private(Resource):
    """
       A resource for accessing private data, available only to authenticated users.
       :param:
           None; authentication is validated through the 'Authorization' header.
       :return:
           JSON response indicating access has been granted with status code.
    """
    @api.doc(security='Bearer Auth')
    @api.doc(responses={200: 'Access granted.'})
    @token_required
    def get(self):
        return {"message": "Access granted."}, 200


@api.route('/verify-otp')
class VerifyOtp(Resource):
    @limiter.limit("10 per hour")
    @api.expect(verify_otp_model)
    @api.doc(
        responses={200: 'OTP verified successfully.', 400: 'Invalid OTP or session.', 401: 'OTP expired or incorrect.'})
    def post(self):
        data = request.get_json()
        session_id = data.get('session_id')
        otp = data.get('otp')

        if not validate_otp_and_session_id(otp, session_id):
            return {"message": "Invalid OTP or session."}, 400

        database = Database(Config.DATABASE_CONFIG)
        # Use session ID to retrieve user information, OTP, and expiration
        user_info = User.get_user_by_session_id(database, session_id)
        if not user_info:
            return {"message": "Invalid session ID."}, 400

        stored_otp = user_info.get('otp')
        otp_expiration = user_info.get('otp_expiration_time')

        # Verify OTP and its expiration
        if otp != stored_otp or datetime.datetime.now() > otp_expiration:
            return {"message": "OTP expired or incorrect."}, 401

        # OTP verification succeeded, issue JWT
        username = user_info.get('username')
        encoded_jwt = AuthenticationService.create_jwt_token(username)
        # Clear the session ID, OTP, and OTP expiration from the user's document
        User.clear_mfa_fields(database, username)
        print(f"User {username} has been fully-authenticated.")

        return {"message": "OTP verified successfully. You're now fully-authenticated", "token": encoded_jwt}, 200


def check_empty_inputs(username, password):
    """
        Checks if the provided username or password are empty.
        :param username: The username to check.
        :param password: The password to check.
        :return: True if either input is empty, False otherwise.
    """
    if not username.strip() or not password.strip():
        return True
    return False


def check_regex_inputs(username, password):
    """
        Validates the username and password against defined regex patterns.
        :param username: The username to validate.
        :param password: The password to validate.
        :return: True if either input fails regex validation, False otherwise.
    """
    username_regex = r"^[a-zA-Z0-9_\-\.]+$"
    password_regex = r"^[a-zA-Z0-9_\-\.!@#$%^&*()+=]{8,64}$"
    if not re.match(username_regex, username) or not re.match(password_regex, password):
        return True
    return False


def validate_user_input(username, password, check_length=False):
    """
    Validates user input for common issues including emptiness, length, and character patterns.
    :param username: The username to validate.
    :param password: The password to validate.
    :param check_length: Flag to determine if password length should be checked.
    :return: Tuple of error message and status code if validation fails, or (None, None) if it passes.
    """
    if check_empty_inputs(username, password):
        return "Username or password cannot be empty.", 400

    if check_length and (len(password) < 8 or len(password) > 64):
        return "Password does not meet the length requirements (max: 8 characters).", 400

    if check_regex_inputs(username, password):
        return "Username or password contains invalid characters.", 400

    return None, None


def validate_phone_number(phone_number):
    """
    Validates a phone number to ensure it contains only digits, starts with '05',
    and contains exactly 10 digits.

    :param phone_number: The phone number as a string.
    :return: True if the phone number is valid, False otherwise.
    """
    if len(phone_number) != 10:
        return False

    # Check if phone number starts with '05'
    if not phone_number.startswith('05'):
        return False

    if not phone_number.isdigit():
        return False

    return True


def validate_otp_and_session_id(otp, session_id):
    """
    Validates an OTP and SessionID for specific criteria.
    OTP should be exactly 6 digits. SessionID should be exactly 16 digits.

    :param otp: The One Time Password to validate.
    :param session_id: The Session ID to validate.
    :return: True if both OTP and SessionID are valid, False otherwise.
    """
    # Validate OTP
    if len(otp) != 6 or not otp.isdigit():
        return False

    # Validate SessionID
    if len(session_id) != 16 or not session_id.isdigit():
        return False

    return True


# SecureFlaskAuth
A Flask-based authentication system featuring SMS-based multi-factor authentication, JWT session management, and well fit security measures.

# Getting Started with Docker
To get the SecureFlaskAuth system up and running locally with Docker, execute the following command in Linux:
```
docker run -d -p 5000:5000 elidorcohen/login:004
```
This command pulls the Docker image elidorcohen/login:004 and runs it in detached mode, mapping the container's port 5000 to port 5000 on the localhost. URL of the Swagger will be: http://localhost:5000/swagger/

# Accessing Swagger UI
Alternatively access the cloud-running Swagger UI to interact with the API at:
http://13.42.164.38:5000/swagger/

# API Endpoint Explanations:
## /auth/register 
```
{
  "username": "string",
  "password": "string",
  "phone_number": "string"
}
```
Allows a new user to register by providing a valid username, password, and phone number. The username and password must be at least 8 characters long. The phone number should follow the format 0508464336. The phone number should be valid and working.

## /auth/login
```
{
  "username": "string",
  "password": "string"
}
```
Users provide their registered username and password for authentication. Upon successful login, an SMS with an OTP (One-Time Password) is sent to the user's registered phone number and a session ID will be returned. However, the user is not fully authenticated at this stage and has not yet received a JWT until completed the entire multi-factor authentication.

## /auth/verify-otp
```
{
  "session_id": "string",
  "otp": "string"
}
```
To complete the authentication process, users must submit the session ID and OTP received during login. A successful verification awards the user a JWT, which is used for accessing protected routes like /auth/private endpoint.

## Authorizing with JWT
1. Click on the "Authorize" button in the Swagger UI.
2. Enter "Bearer < JWT >" in the value field, where < JWT > is the token received after OTP verification.
3. Click "Authorize" and then "Close" to apply the authentication token.

## /auth/private
This endpoint is accessible only to fully authenticated users. If authentication succeeds, the response is "Access granted." Otherwise, an appropriate error message is returned.

## Video Reference
For a visual guide on how to use SecureFlaskAuth, including a step-by-step demonstration of a successful login process via Swagger UI, please refer to our video tutorial. This video showcases how to navigate the authentication flow, from registration to receiving an OTP via SMS and ultimately accessing protected routes using the issued JWT. Watch the video [here](https://drive.google.com/file/d/1hHI3DvLpgIEcEgpOXX-vlFmKvlWHmlHf/view?usp=sharing) to see SecureFlaskAuth in action:

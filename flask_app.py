from flask import Flask
from SecureFlaskAuth.extensions import limiter
import logging
from flask_restx import Api
from routes.routes import api as auth_namespace

logger = logging.getLogger(__name__)

def create_app():
    """
        Initializes and configures the Flask application.

        This function sets up the core components of the Flask application, including
        the API documentation, rate limiting, database configuration, and authentication
        mechanisms. It serves as the entry point for configuring Flask extensions,
        blueprints, and other application-wide settings.

        :return:
            Flask app: The configured Flask application instance ready for running.

        The function performs the following steps:
        1. Initializes the Flask application and configures it for API documentation using Flask-RESTx.
        2. Sets up API security authorizations for JWT Bearer token authentication, indicating how
           clients should authenticate with the API.
        3. Initializes the Flask-Limiter extension with the app to enforce rate limiting on endpoints,
           providing basic protection against DDoS attacks and brute-force attempts.
        4. Configures the database connection using settings from the application's configuration. This
           step is crucial for data persistence and access throughout the application.
        5. Registers the authentication namespace (auth_namespace) with the API, organizing all
           authentication-related routes under a common path (`/auth`).

        Security Considerations:
        - The API is configured to use Bearer Auth for securing endpoints, requiring clients to provide
          a valid JWT in the Authorization header for accessing protected resources.
        - Rate limiting is applied globally to help against abusive requests and ensure the API remains
          responsive under high traffic.
        """
    logger.info('Initializing Flask application...')
    app = Flask(__name__)
    api = Api(app, version='1.0', title='My API', description='A simple API', doc='/swagger/',
              authorizations={
                  'Bearer Auth': {
                      'type': 'apiKey',
                      'in': 'header',
                      'name': 'Authorization'
                  },
              })
    logger.info('Flask application initialized.')

    logger.info('Configuring limiter...')
    limiter.init_app(app)
    logger.info('Limiter configured.')

    logger.info('Adding namespaces to the API...')
    api.add_namespace(auth_namespace, path='/auth')
    logger.info('Namespaces added to the API.')

    return app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask-Limiter for rate limiting capabilities.
# The Limiter uses the client's IP address using get_remote_address function
# to apply rate limits, ensuring that no single
# user can make more than 5 requests per hour by default across all routes.
# This provides basic protection against DDoS attacks and brute-force attempts.

limiter = Limiter(key_func=get_remote_address, default_limits=["10 per hour"])




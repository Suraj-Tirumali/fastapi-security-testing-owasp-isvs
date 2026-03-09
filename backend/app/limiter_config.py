# -----------------------------
# Import Limiter and utility function
# -----------------------------
from slowapi import Limiter                     # Limiter class to apply rate limiting
from slowapi.util import get_remote_address     # Function to extract client's IP address

# -----------------------------
# Initialize Limiter with IP-based rate limiting
# -----------------------------
limiter = Limiter(key_func=get_remote_address)  # Uses client IP as the key for rate limiting
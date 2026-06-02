"""General scripts that help with using any API."""

# Third-Party Libraries
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def create_retry_session(
    retries=5, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504)
):
    """Create a requests Session with automatic retry and backoff logic."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,  # Max retries across all failure types
        read=retries,  # Max retries for read errors
        connect=retries,  # Max retries for connection errors
        backoff_factor=backoff_factor,  # Delay grows exponentially: <backoff_factor> x 2^(<num_total_retries> - 1))
        status_forcelist=status_forcelist,  # Retry on these specific status codes
        allowed_methods=["GET", "POST", "PUT"],  # Methods to retry
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

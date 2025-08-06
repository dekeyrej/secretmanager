import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# The following methods handle encoding and decoding of data to/from base64.
def encode_data(data):
    """Encodes data to base64."""
    encoded = base64.b64encode(data.encode("utf-8")).decode("utf-8")
    logger.debug(f"Encoded data: {encoded}")
    return encoded


def decode_data(data):
    """Decodes base64 encoded data."""
    decoded = base64.b64decode(data.encode("utf-8")).decode("utf-8")
    logger.debug(f"Decoded data: {decoded}")
    return decoded

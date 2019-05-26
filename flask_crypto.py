# Third party imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random

# Standard lib imports
import warnings
import base64


class FlaskCrypto:
    def __init__(self, app=None):
        self.key = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        if not app.config.get('AES_CRYPTO_KEY'):
            warnings.warn('AES_CRYPTO_KEY not set')
            return
        self.key = app.config.get('AES_CRYPTO_KEY').encode('utf-8')

    def encrypt(self, text):
        if not isinstance(text, str):
            raise TypeError("text should be a string")
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        encrypted_text = cipher.encrypt(pad(iv + text.encode('utf-8'), AES.block_size))
        return base64.b64encode(encrypted_text)

    def decrypt(self, cypher_text):
        if not isinstance(cypher_text, str):
            raise TypeError("cypher_text should be a string")
        decoded = base64.b64decode(cypher_text)
        iv = decoded[:AES.block_size]
        text = decoded[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(text), AES.block_size)

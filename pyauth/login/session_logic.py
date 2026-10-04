from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
import secrets
from typeguard import typechecked

SECONDS_IN_A_WEEK = 604800
class TokenExpired(Exception):
    """Raised when a token's timestamp has expired."""
    pass
class TokenInvalid(Exception):
    """Raised when a token has an invalid signature or has been tampered with."""
    pass


class Session:
    """
    Manages the creation, signing, and verification of session tokens.

    This class uses `itsdangerous` to create cryptographically signed and
    timestamped tokens to prevent tampering and token hijacking.

    Raises:
        TokenExpired: Raised by `unsign_token` if the token has passed its maximum age.
        TokenInvalid: Raised by `unsign_token` if the token's signature is invalid.
    """
    @typechecked
    def __init__(self, secret_key: str):
        """
        Initializes the Session handler with a secret key.

        Args:
            secret_key (str): The secret key used for all cryptographic signing operations.
        """
        self.secret_key = secret_key
        self.signer = TimestampSigner(secret_key)

    @typechecked
    def generate_token(self) -> str:
        """
        Generates a cryptographically secure, URL-safe random string to be used as a token.

        Returns:
            str: A new, unsigned token.
        """
        return secrets.token_urlsafe(64)
        
    @typechecked
    def sign_token(self,token:str) -> str:
        """
        Signs a given token with a timestamp.

        Args:
            token (str): The raw token string to sign.

        Returns:
            str: The signed and timestamped token string.
        """
        signed_token = self.signer.sign(token) 
        return signed_token.decode()

    @typechecked
    def generate_and_sign_token(self) -> tuple[str,str]:
        """
        Generates a new token and signs it in a single operation.

        Returns:
            tuple[str,str]: A tuple containing the original raw token and the signed token.
        """
        token = secrets.token_urlsafe(64)
        signed_token = self.signer.sign(token)
        return token, signed_token.decode()

    @typechecked
    def unsign_token(self, signed_token: str, max_age:int =SECONDS_IN_A_WEEK) -> str:
        """
        Verifies a signed token's signature and timestamp.

        Args:
            signed_token (str): The signed token string to verify.
            max_age (int, optional): The maximum age of the token in seconds. Defaults to one week.

        Raises:
            TokenExpired: Raised if the token's timestamp is older than `max_age`.
            TokenInvalid: Raised if the token's signature is invalid or it has been tampered with.

        Returns:
            str: The original, unsigned token string if verification is successful.
        """
        try:
            session_id = self.signer.unsign(signed_token, max_age=max_age )
            return session_id.decode()
        except SignatureExpired:
            raise TokenExpired('Token Expired.')
        except BadSignature:
            raise TokenInvalid('The token is Invalid or has been tampered')
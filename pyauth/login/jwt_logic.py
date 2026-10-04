import time
import jwt
from typeguard import typechecked
import secrets



# refresh token rotation
# bff send as cookie else localstorage


#Content Security Policy (CSP): Implement a strict CSP to limit where scripts can be loaded from and what they can do.
#Input Sanitization & Output Encoding: Rigorously sanitize all user inputs and encode all outputs to prevent script injection.


#trade off....


# take into consideration mutliple logins form diff device

class TokenExpired(Exception):
    """Exception raised when a JWT has expired."""
    pass

class TokenInvalid(Exception):
    """Exception raised when a JWT is invalid (e.g., malformed, invalid signature)."""
    pass

class JWT:
    """
    Manages the creation, decoding, and handling of JSON Web Tokens (JWTs).

    This class provides functionalities for generating access and refresh tokens,
    as well as validating access tokens using a defined secret key and expiration policy.
    It is designed to support authentication mechanisms in applications.

    Raises:
        TokenExpired: If `decode_access_token` encounters a token that has passed its expiry time.
        TokenInvalid: If `decode_access_token` encounters a token that is malformed, has an
                      invalid signature, or fails other validation checks.

    Returns:
        JWT: An instance of this class, configured to manage JWTs.
    """
    @typechecked
    def __init__(self, secret_key: str, expiry: float = 3600) -> None:
        """
        Initializes the JWT handler with a secret key and token expiry.

        Args:
            secret_key (str): The secret key used for signing and verifying JWTs.
            expiry (float, optional): The duration in seconds for which an access token is valid.
                                      Defaults to 3600 (1 hour).
        """
        self.secret_key = secret_key
        self.expiry = expiry


    # Refresh tokens go in the go in cookie
    # take into account cors and csrf
    @typechecked
    def create_refresh_token(self) -> str:
        """
        Generates a cryptographically secure refresh token.

        Refresh tokens are typically long-lived and are used to obtain new access tokens
        without requiring the user to re-authenticate.

        Returns:
            str: A securely generated, URL-safe refresh token string.
        """
        return secrets.token_urlsafe(64)

    # Access tokens go in the Authorization header
    @typechecked
    def create_access_token(self, user_id: str | float) -> str:
        """
        Creates a JWT access token for a given user ID.

        The access token includes the user ID and an expiration timestamp.
        It is signed with the secret key.

        Args:
            user_id (str | float): The unique identifier for the user (e.g., username or numeric ID).

        Returns:
            str: The encoded JWT access token as a string.
        """
        payload: dict[str, str | float]
        payload = {
            "user_id": user_id,
            "exp": time.time() + self.expiry
        }

        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    @typechecked
    def decode_access_token(self, token: str) -> dict[str, str]:
        """
        Decodes and validates a JWT access token.

        It verifies the token's signature and checks for expiration.

        Args:
            token (str): The JWT access token string to be decoded.

        Raises:
            TokenExpired: If the token has passed its expiration time.
            TokenInvalid: If the token is malformed, has an invalid signature, or is otherwise invalid.

        Returns:
            dict[str, str]: The `user_id` extracted from the token's payload upon successful decoding and validation.
                            (Note: The function signature's return type is `dict[str, str]`, but the current
                            implementation extracts and returns the `user_id` value directly from the payload,
                            which is of type `str` or `float`).
        """
        try:
            # The following line returns the user_id directly, not a dict.
            # The type hint dict[str, str] for the return value is inconsistent with this.
            # The docstring reflects the signature's type hint but clarifies what is returned.
            return jwt.decode(token, self.secret_key, algorithms=["HS256"])['user_id']
        except jwt.ExpiredSignatureError:
            raise TokenExpired({"error": "Token has expired"})
        except jwt.InvalidTokenError:
            raise TokenInvalid({"error": "Invalid token"})

    @typechecked
    def create_access_and_refresh_token(self, user_id: str | float) -> tuple[str, str]:
        """
        Creates both a new access token and a new refresh token for a specified user.

        This is a convenience method typically used during login or when a refresh token
        is successfully used to obtain a new pair of tokens.

        Args:
            user_id (str | float): The unique identifier for the user.

        Returns:
            tuple[str, str]: A tuple containing the new access token (string) as the first element
                             and the new refresh token (string) as the second element.
        """
        return self.create_access_token(user_id), self.create_refresh_token()
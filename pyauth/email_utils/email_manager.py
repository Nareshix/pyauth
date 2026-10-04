import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typeguard import typechecked
from itsdangerous import URLSafeTimedSerializer,BadSignature, SignatureExpired

class RecipientsRefused(Exception):
    """Raised when the SMTP server refuses one or more recipient email addresses."""
    pass

class EmailLinkExpired(Exception):
    """Raised when an email confirmation link has passed its expiration time."""
    pass

class EmailLinkInvalid(Exception):
    """Raised when an email confirmation link is malformed or has an invalid signature."""
    pass

class SMTPError(Exception):
    """A generic error occurred during an SMTP operation."""
    pass

class SMTPAuthError(Exception):
    """Raised when SMTP authentication fails (e.g., incorrect username/password)."""
    pass


class _TokenManager:
    """
    Manages the generation and verification of time-sensitive tokens.

    This class uses  to create secure and timestamped tokens.
    This is often used for email confirmation, password resets, etc.
    """
    @typechecked
    def __init__(self, secret_key:str) -> None:
        """
        Initializes the TokenManager with a secret key.

        Args:
            secret_key (str): The secret key used for signing and verifying tokens.
                              It should be kept confidential.
        """
        self.secret_key = secret_key

    # IMPORTANT: Salt is often used to distinguish the context
    @typechecked
    def generate_token(self, email:str, salt:str) -> str:
        """
        Generates a time-sensitive token for a given email and salt.

        Args:
            email (str): The email address to be encoded in the token.
            salt (str): A salt value to differentiate tokens used for different purposes
                        (e.g., 'email-confirmation', 'password-reset').

        Returns:
            str: The generated URL-safe, timed token.
        """
        serialiser = URLSafeTimedSerializer(self.secret_key, salt=salt)
        token = serialiser.dumps(email)
        return token

    @typechecked
    def get_email_from_token(self, salt:str, token:str, timer:int = 600) -> str:
        """
        Verifies a token and retrieves the email address if valid and not expired.

        Args:
            salt (str): The salt value that was used to generate the token.
            token (str): The token to be verified.
            timer (int, optional): The maximum age of the token in seconds.
                                   Defaults to 600 seconds (10 minutes).

        Returns:
            str: The email address extracted from the token if valid and not expired.

        Raises:
            SignatureExpired: If the token has expired.
            BadSignature: If the token is invalid or has been tampered with.
        """
        serialiser = URLSafeTimedSerializer(self.secret_key, salt=salt)
        email = serialiser.loads(token, max_age=timer)
        return email
        
        

class EmailUtils:
    """
    Provides utilities for sending emails and confirming email addresses using tokens.

    This class handles the construction and sending of emails, including generating
    confirmation links with time-sensitive tokens. It also provides a method
    to verify these tokens.

    Raises:
        RecipientsRefused: If the recipient's email address is refused by the SMTP server.
        SMTPAuthError: If SMTP authentication fails (e.g., wrong email/password).
        SMTPError: For other SMTP-related errors during email sending.
        EmailLinkExpired: If a confirmation link/token has expired.
        EmailLinkInvalid: If a confirmation link/token is invalid or tampered with.

    Returns:
        An instance of EmailUtils.
    """
    @typechecked
    def __init__(self, sender_email:str, sender_email_password:str, secret_key:str) -> None:
        """
        Initializes the EmailUtils instance.

        Args:
            sender_email (str): The email address from which emails will be sent.
            sender_email_password (str): The password for the sender's email account.
            secret_key (str): The secret key for generating and verifying tokens.
                              This is passed to the internal _TokenManager.
        """
        self.sender_email = sender_email
        self.sender_email_password = sender_email_password
        self.token_manager = _TokenManager(secret_key)
    
    @typechecked
    def send_email(self,backend_api_url:str, receiver_email:str, salt:str, email_msg:str = '', email_subject:str = '') -> bool:
        """
        Sends an email containing a tokenized link for confirmation or other actions.

        Args:
            backend_api_url (str): The base URL of the backend API endpoint that will handle
                                   the token. A trailing slash will be added if missing.
                                   
            receiver_email (str): The email address of the recipient.
            
            salt (str): A salt value to be used by the TokenManager for generating the token,
                        distinguishing its purpose (e.g., 'email-verification').
                        
            email_msg (str, optional): The main body/message of the email. The generated
                                       confirmation link will be appended to this message.
                                       Defaults to ''.

            email_subject (str, optional): The subject line of the email. Defaults to ''.

        Raises:
            RecipientsRefused: If the `receiver_email` is refused by the SMTP server.
            SMTPAuthError: If authentication with the SMTP server fails (incorrect sender credentials).
            SMTPError: For other SMTP-related issues during email sending.

        Returns:
            bool: True if the email was sent successfully.
        """
        if not backend_api_url.endswith('/'):
            backend_api_url += '/'

        message = MIMEMultipart()
        message["From"] = self.sender_email
        message["To"] = receiver_email
        message["Subject"] = email_subject

        token = self.token_manager.generate_token(receiver_email ,salt)
        url = backend_api_url + token
        email_msg += f"\n\n{url}"
        
        message.attach(MIMEText(email_msg, "plain"))

        # Connect to the SMTP server and send the email
        try:
            # For Gmail
            with smtplib.SMTP("smtp.gmail.com", 587)  as server:
                server.starttls()  # Encrypts the connection
                server.login(self.sender_email, self.sender_email_password)  # Login to the server
                server.sendmail(self.sender_email, receiver_email, message.as_string())  # Send the email
            return True
        
        except smtplib.SMTPRecipientsRefused:
            raise RecipientsRefused(f'{receiver_email} does not exist')

        except smtplib.SMTPAuthenticationError:
            raise SMTPAuthError('SMTP Email and Password does not match')

        except smtplib.SMTPException as e:  # type: ignore
            raise SMTPError(f'Unable to send email due to {e}')
        
    @typechecked
    def confirm_email(self, salt:str ,token:str, timer:int = 600) -> str:
        """
        Confirms an email address by verifying a provided token.

        Args:
            salt (str): The salt value that was used when the token was generated.
            token (str): The token received (e.g., from a confirmation link).
            timer (int, optional): The maximum age (in seconds) the token is allowed to have.
                                   Defaults to 600 seconds (10 minutes).

        Raises:
            EmailLinkExpired: If the token has expired (older than `timer` seconds).
            EmailLinkInvalid: If the token is malformed, has an invalid signature, or the
                              salt does not match.

        Returns:
            str: The email address associated with the token if it's valid and not expired.
        """
        try:
            email = self.token_manager.get_email_from_token(salt, token, timer)
            return email
        except SignatureExpired:
            raise EmailLinkExpired("Email Link has been expired (Token expired)")

        except BadSignature:
            raise EmailLinkInvalid("Email Link is invalid (Token Invalid)")

        # except Exception as e:  # fallback, use it for logging
        #     return str(e)

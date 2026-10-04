from typing import List
from zxcvbn import zxcvbn
from email_validator import validate_email, EmailNotValidError
from typeguard import typechecked

class InvalidEmail(Exception):
    """Exception raised when an email address is not valid according to validation rules."""
    pass


@typechecked
def get_password_strength_suggestions(password:str, user_inputs: List[str] | None = None) -> List[str]:
    """
    checks whether password is strong. 
    If password is weak, it will return a list of password_suggestion.
    Else, it will return an empty list, suggesting that the password is strong enough to not have any suggestions 

    Args:
        password (str): password
        user_inputs (List[str] | None, optional): other inputs like username,email etc. Defaults to None.

    Raises:
        TypeError: If the provided `password` is not a string.
        ValueError: If the provided `password` is an empty string.

    Returns:
        List[str]: ways passwords can be improved
    """


    if password == '':
        raise ValueError("Password cannot be empty")


    results = zxcvbn(password, user_inputs=user_inputs)

    password_suggestion = results['feedback']['suggestions']
    if password_suggestion == []:
        return []  # Password is strong
    return password_suggestion # Password is weak

@typechecked
def sanitise_email(email:str, first_time:bool = False) -> str:
    """
    Validates and normalizes an email address.

    This function uses the `email_validator` library to check if the email address
    is syntactically valid and, optionally, if its domain has DNS records
    (indicating potential deliverability). It returns a normalized version of the email.

    Args:
        email (str): The email address string to be validated and sanitized.
        first_time (bool, optional): If True, enables deliverability checks (DNS lookup).
                                     This is typically True for new user sign-ups.
                                     Defaults to False.

    Raises:
        InvalidEmail: If the email address is found to be invalid (e.g., bad syntax,
                      non-existent domain when `first_time` is True). The exception
                      message contains a human-readable explanation.

    Returns:
        str: The normalized (sanitized) email address if it is valid.
    """
    try:
        # check_deliverability should be True for first time sign up, else False
        # This has to do with checking DNS and rejecting providers that dont exist
        emailinfo = validate_email(email, check_deliverability=first_time)

        email = emailinfo.normalized
        return email

    except EmailNotValidError as e:
    # The exception message is human-readable!
        raise InvalidEmail(str(e))
import re
import time

from pyauth import EmailLinkExpired, EmailLinkInvalid, EmailUtils , RecipientsRefused, SMTPAuthError
from pyauth.email_utils.email_manager import  _TokenManager  # type: ignore

from dotenv import load_dotenv
import os
import pytest


load_dotenv()
sender_email = str(os.getenv('SENDER_EMAIL'))
receiver_email = str(os.getenv('RECIEVER_EMAIL'))
sender_password = str(os.getenv('EMAIL_PASSWORD'))
secret_key = 'test-key'

salt = 'test-salt'


email_utils_test = EmailUtils(sender_email, sender_password,secret_key)

# Check your email
def test_email_sent_successfully():
    # first argument is just empty backend api. Ignore the / in the beginning of the 
    # token recieved in email because it is added in case user does not add a /
    # at the end of their backend api url
    assert email_utils_test.send_email('',receiver_email,salt)



def test_invalid_email_address():
    with pytest.raises(RecipientsRefused, match=f"asfdasdf does not exist"):
        email_utils_test.send_email('', 'asfdasdf', salt)


def test_wrong_password_of_sender():
    tmp = EmailUtils(sender_email, 'WRONG-PASSWORD',secret_key)
    with pytest.raises(SMTPAuthError, match= 'SMTP Email and Password does not match'):
        tmp.send_email('', receiver_email, salt) 


def test_wrong_email_of_sender():
    tmp = EmailUtils('WRONG_EMAIL@WRONG.com', sender_password,secret_key)
    with pytest.raises(SMTPAuthError, match= 'SMTP Email and Password does not match'):
        tmp.send_email('', receiver_email, salt) 



def test_confirm_email():
    token_manager = _TokenManager(secret_key)
    token =token_manager.generate_token(receiver_email,salt)
    assert receiver_email == email_utils_test.confirm_email(salt,token)


def test_confirm_email_expired():
    token_manager = _TokenManager(secret_key)
    token = token_manager.generate_token(receiver_email,salt)
    time.sleep(2)
    with pytest.raises(EmailLinkExpired, match=re.escape('Email Link has been expired (Token expired)')):
        email_utils_test.confirm_email(salt,token,1)

def test_confirm_invalid_email():
    with pytest.raises(EmailLinkInvalid, match=re.escape('Email Link is invalid (Token Invalid)')):
        email_utils_test.confirm_email(salt,'INVALID_TOKEN_HENCE_INVALID_EMAIL_LINK')

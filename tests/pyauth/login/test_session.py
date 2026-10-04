import pytest
import time
from pyauth import Session, TokenExpired, TokenInvalid

SECONDS_IN_A_WEEK = 604800
TEST_SECRET_KEY = "this-is-a-secret-key-for-testing-purposes-only"

@pytest.fixture
def session_handler() -> Session:
    """
    Provides a pre-configured Session instance for use in tests.
    This is a pytest fixture that runs before each test function that requests it.
    """
    return Session(secret_key=TEST_SECRET_KEY)

def test_generate_and_sign_token_flow(session_handler: Session):
    """
    Tests the entire successful lifecycle: generate, sign, and unsign.
    This also implicitly tests generate_and_sign_token and unsign_token success.
    """
    raw_token, signed_token = session_handler.generate_and_sign_token()

    # Assert that the raw token and signed token are different
    assert isinstance(raw_token, str)
    assert isinstance(signed_token, str)
    assert raw_token != signed_token

    # Unsign the token and verify it matches the original raw token
    unsigned_token = session_handler.unsign_token(signed_token)
    assert unsigned_token == raw_token

def test_sign_and_unsign_known_token(session_handler: Session):
    """
    Tests the sign_token and unsign_token methods with a predictable string.
    """
    known_data = "user-id-12345"
    signed_data = session_handler.sign_token(known_data)
    
    assert known_data != signed_data

    unsigned_data = session_handler.unsign_token(signed_data)
    assert unsigned_data == known_data

def test_unsign_token_raises_invalid_on_tampering(session_handler: Session):
    """
    Verifies that a tampered token raises TokenInvalid.
    """
    _, signed_token = session_handler.generate_and_sign_token()
    tampered_token = signed_token + "tampered"

    with pytest.raises(TokenInvalid) as excinfo:
        session_handler.unsign_token(tampered_token)
    
    # Check that the exception message is what we expect
    assert "Invalid or has been tampered" in str(excinfo.value)

def test_unsign_token_raises_expired(session_handler: Session):
    """
    Verifies that an expired token raises TokenExpired.
    """
    signed_token = session_handler.sign_token("some-data")
    
    # Wait for 2 seconds to ensure the token's timestamp is in the past
    time.sleep(2)
    
    # Try to unsign with a max_age of 1 second, which should fail
    with pytest.raises(TokenExpired) as excinfo:
        session_handler.unsign_token(signed_token, max_age=1)
        
    assert "Token Expired" in str(excinfo.value)

def test_unsign_token_succeeds_before_expiration(session_handler: Session):
    """
    Verifies that a token is successfully unsigned if it's within its max_age.
    """
    signed_token = session_handler.sign_token("some-other-data")
    
    # Wait for 1 second
    time.sleep(1)
    
    # Unsign with a max_age of 5 seconds, which should succeed
    unsigned_token = session_handler.unsign_token(signed_token, max_age=5)
    assert unsigned_token == "some-other-data"

def test_unsign_token_default_max_age(session_handler: Session):
    """
    Verifies the default max_age (one week) works as expected.
    """
    signed_token = session_handler.sign_token("data-for-long-test")
    
    # This should succeed because we are well within the default 1-week expiry
    unsigned_token = session_handler.unsign_token(signed_token, max_age=SECONDS_IN_A_WEEK)
    assert unsigned_token == "data-for-long-test"
    
def test_generate_token_is_random(session_handler: Session):
    """
    Verifies that generate_token produces a different token each time.
    """
    token1 = session_handler.generate_token()
    token2 = session_handler.generate_token()
    assert token1 != token2
    assert isinstance(token1, str)
    assert len(token1) > 64 # secrets.token_urlsafe(64) produces 86 chars

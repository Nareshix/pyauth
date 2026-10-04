#type: ignore
import pytest
from pyauth import InvalidEmail, get_password_strength_suggestions, sanitise_email


def test_strong_password():
    """Tests that a strong password returns no suggestions."""
    assert get_password_strength_suggestions('lC*2(F6q3zEG.') == []

def test_weak_password():
    """Tests that a weak password returns the expected suggestions."""
    suggestions = get_password_strength_suggestions('abc')
    assert 'Avoid sequences.' in suggestions
    assert 'Add another word or two. Uncommon words are better.' in suggestions

def test_empty_password_raises_value_error():
    """Tests that an empty password raises a ValueError."""
    with pytest.raises(ValueError, match='Password cannot be empty'):
        get_password_strength_suggestions('')


# REFACTORED: Consolidate all valid email tests into one.
@pytest.mark.parametrize(
    "input_email, expected_output",
    [
        # The local-part (before @) should maintain its case
        ("valid@gmail.com", "valid@gmail.com"),
        ("VALID@gmail.com", "VALID@gmail.com"),
        # The domain-part (after @) should always be lowercased
        ("valid@gMaIL.com", "valid@gmail.com"),
        ("valid@gmail.COM", "valid@gmail.com"),
        ("valid@GMAIL.COM", "valid@gmail.com"),
    ]
)
def test_sanitise_email_valid_cases(input_email, expected_output):
    """
    Tests that various valid email formats are sanitized correctly.
    This covers both first_time=True and first_time=False, as the
    logic for these valid inputs is the same.
    """
    # Test with first_time=False (default)
    assert sanitise_email(input_email) == expected_output
    # Test explicitly with first_time=True
    assert sanitise_email(input_email, first_time=True) == expected_output


@pytest.mark.parametrize("invalid_email", [
    "ads",
    "plainaddress",
    "missing@domain",
    "@missinguser.com",
    "missingdomain@.com",
    "missingdot@domaincom",
    "two@@signs.com",
    "has space@example.com",
    "user@.com",
    "user@com",
])
def test_sanitise_email_invalid_cases_raise_error(invalid_email):
    """Tests that various invalid email formats raise InvalidEmail."""
    with pytest.raises(InvalidEmail):
        sanitise_email(invalid_email)
    
    # Also verify it fails with first_time=True
    with pytest.raises(InvalidEmail):
        sanitise_email(invalid_email, first_time=True)
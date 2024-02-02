import re


class Validator(object):
    """
    Check the validity of the entered email, username and password for a
    newly registered user.
    """
    def __init__(self) -> None:
        pass

    def validate_email(self, email: str) -> bool:
        """
        Checks the validity of the entered email, which includes the
        presence of '@' and the length of the email.

        :param email: The email to be validated.

        :return: Validity of entered email.
        """
        return "@" in email and 2 < len(email) < 320

    def validate_username(self, username: str) -> bool:
        """
        Checks the validity of the entered username, which includes the
        presence of certain characters (a-z, A-Z, 0-9, _, -) and the
        length of the username (1-20 characters).

        :param username: The usernmame to be validated.

        :return: Validity of entered username.
        """
        pattern = r"^[a-zA-Z0-9_-]{1,20}$"
        return bool(re.match(pattern, username))

    def validate_password(self, password: str,
                          weak_passwords: list=[]) -> bool:
        """
        Checks the validity of the entered password, which includes:
        - Length (8-64 characters)
        - Presence of digits
        - Presence of uppercase letters
        - Presence of lowercase letters
        - Presence of symbols
        - Absence of weak passwords (optional)

        :param password: The password to be validated.
        :param weak_passwords: List of weak passwords that shouldn't be
            used.

        :return: Validity of entered password.
        """
        # calculating the length
        length_short_error = len(password) < 8
        length_long_error = len(password) > 64

        # searching for digits
        digit_error = re.search(r"\d", password) is None

        # searching for uppercase
        uppercase_error = re.search(r"[A-Z]", password) is None

        # searching for lowercase
        lowercase_error = re.search(r"[a-z]", password) is None

        # searching for symbols
        symbol_error = re.search(r"\W", password) is None

        # searching for weak passwords
        weak_password_error = password in weak_passwords

        # overall result
        if (length_short_error or length_long_error or
                digit_error or uppercase_error or
                lowercase_error or symbol_error or
                weak_password_error):
            return False
        else:
            return True

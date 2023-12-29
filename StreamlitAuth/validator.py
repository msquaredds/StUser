import re

class Validator:
    """
    This class will check the validity of the entered username, name, and email for a 
    newly registered user.
    """
    def validate_email(self, email: str) -> bool:
        """
        Checks the validity of the entered email.

        Parameters
        ----------
        email: str
            The email to be validated.
        Returns
        -------
        bool
            Validity of entered email.
        """
        return "@" in email and 2 < len(email) < 320

    def validate_username(self, username: str) -> bool:
        """
        Checks the validity of the entered username.

        Parameters
        ----------
        username: str
            The usernmame to be validated.
        Returns
        -------
        bool
            Validity of entered username.
        """
        pattern = r"^[a-zA-Z0-9_-]{1,20}$"
        return bool(re.match(pattern, username))

    def validate_password(self, password: str) -> bool:
        """
        Checks the validity of the entered password.

        Parameters
        ----------
        password: str
            The password to be validated.
        Returns
        -------
        bool
            Validity of entered password.
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

        # overall result
        if (length_short_error or length_long_error or
                digit_error or uppercase_error or
                lowercase_error or symbol_error):
            return False
        else:
            return True

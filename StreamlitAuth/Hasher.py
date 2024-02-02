from argon2 import PasswordHasher


class Hasher(object):
    """
    Hash plain text passwords.
    """
    def __init__(self, passwords: list):
        """
        :param passwords: The list of plain text passwords to be hashed.
        """
        self.passwords = passwords

        self.ph = PasswordHasher()

    def _hash(self, password: str) -> str:
        """
        Hashes the plain text password.

        :param password: The plain text password to be hashed.

        :return: The hashed password.
        """
        return self.ph.hash(password)

    def generate(self) -> list:
        """
        Hashes the list of plain text passwords.

        :return: The list of hashed passwords.
        """
        return [self._hash(password) for password in self.passwords]

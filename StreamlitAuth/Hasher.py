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

    def _verify(self, hash: str, password: str) -> bool:
        """
        Verifies the password against the hash.

        :param hash: The hash to verify against.
        :param password: The password to verify.

        :return: True if the password matches the hash, False otherwise.
        """
        return self.ph.verify(hash, password)

    def check(self, hashes: list) -> list:
        """
        Verifies the passwords against the hashes. The hashes must be in
        the same order as the hashes or they won't match.

        :param hashes: The hashes to verify against.

        :return: True if the password matches the hash, False otherwise.
            This is a list in order of the passwords and hashes.
        """
        return [self._verify(hash, password) for hash, password
                in zip(hashes, self.passwords)]

"""
This module provides classes for encrypting and decrypting messages.
"""

import crcmod
import base64

from cryptography.fernet import Fernet
from google.oauth2.service_account import Credentials
from google.cloud import kms
from typing import Tuple

from StreamlitAuth import ErrorHandling as eh


class GenericEncryptor(object):
    """
    Encrypt and decrypt messages using the Fernet symmetric encryption.
    """
    def __init__(self) -> None:
        pass

    def encrypt(self, plaintext: str) -> Tuple[bytes, bytes]:
        """Derive a symmetric key and encrypt the message."""
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(plaintext.encode("utf-8"))
        return key, token

    def decrypt(self, key: bytes, token: bytes) -> str:
        """Decrypt a message using the key."""
        f = Fernet(key)
        plaintext = f.decrypt(token)
        return plaintext.decode("utf-8")


class GoogleEncryptor(object):
    """
    Encrypt and decrypt messages using the Google API.
    project_id (string): Google Cloud project ID (e.g. 'my-project').
    location_id (string): Cloud KMS location (e.g. 'us-east1').
    key_ring_id (string): ID of the Cloud KMS key ring (
        e.g. 'my-key-ring').
    key_id (string): ID of the key to use (e.g. 'my-key').
    kms_credentials (google.oauth2.service_account.Credentials):
        The credentials to use for the KMS (Key Management
        Service).

        For example, you can set up a service account in the same
        google cloud project that has the KMS. This service
        account must be permissioned (at a minimum) as a "Cloud
        KMS CryptoKey Encrypter" in order to use the KMS here.

        Example code to get the credentials (you must install
            google-auth-oauthlib and google-auth in your
            environment):
            from google.oauth2 import service_account
            scopes = ['https://www.googleapis.com/auth/cloudkms']
            # this is just a file that stores the key info (the
            # service account key, not the KMS key) in a JSON file
            our_credentials = 'service_account_key_file.json'
            creds = service_account.Credentials.from_service_account_file(
                our_credentials, scopes=scopes)
    """
    def __init__(
            self, project_id: str, location_id: str, key_ring_id: str,
            key_id: str, kms_credentials: Credentials = None) -> None:
        self.project_id = project_id
        self.location_id = location_id
        self.key_ring_id = key_ring_id
        self.key_id = key_id
        self.kms_credentials = kms_credentials

    def _crc32c(self, data: bytes) -> int:
        """
        Calculates the CRC32C checksum of the provided data.

        :param data: The bytes over which the checksum should be
            calculated.

        :return: An int representing the CRC32C checksum of the provided
            bytes.
        """
        crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
        return crc32c_fun(data)

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt plaintext using a symmetric key.

        :param plaintext: Message to encrypt.

        :return encrypt_response: Encrypted ciphertext.
        """
        # Convert the plaintext to bytes.
        plaintext_bytes = plaintext.encode("utf-8")

        # Compute plaintext's CRC32C.
        plaintext_crc32c = self._crc32c(plaintext_bytes)

        # Create the client.
        client = kms.KeyManagementServiceClient(
            credentials=self.kms_credentials)
        # Build the key name.
        key_name = client.crypto_key_path(self.project_id, self.location_id,
                                          self.key_ring_id, self.key_id)

        # Call the API.
        encrypt_response = client.encrypt(
            request={
                "name": key_name,
                "plaintext": plaintext_bytes,
                "plaintext_crc32c": plaintext_crc32c,
            }
        )

        # Perform integrity verification on encrypt_response.
        # For more details on ensuring E2E in-transit integrity to and
        # from Cloud KMS visit:
        # https://cloud.google.com/kms/docs/data-integrity-guidelines
        if not encrypt_response.verified_plaintext_crc32c:
            eh.add_dev_error(
                'GoogleEncryptor',
                "The request sent to google to encrypt the data was "
                "corrupted in-transit.")
        if not encrypt_response.ciphertext_crc32c == self._crc32c(
                encrypt_response.ciphertext):
            eh.add_dev_error(
                'GoogleEncryptor',
                "The response received from google when encrypting the "
                "data was corrupted in-transit.")

        return encrypt_response

    def decrypt(self, ciphertext: bytes) -> kms.DecryptResponse:
        """
        Decrypt the ciphertext using the symmetric key

        :param ciphertext: Encrypted bytes to decrypt.

        :return decrypt_response: Response including plaintext.
        """
        # Create the client.
        client = kms.KeyManagementServiceClient(
            credentials=self.kms_credentials)
        # Build the key name.
        key_name = client.crypto_key_path(self.project_id, self.location_id,
                                          self.key_ring_id, self.key_id)

        # Compute ciphertext's CRC32C.
        ciphertext_crc32c = self._crc32c(ciphertext)

        # Call the API.
        decrypt_response = client.decrypt(
            request={
                "name": key_name,
                "ciphertext": ciphertext,
                "ciphertext_crc32c": ciphertext_crc32c,
            }
        )

        # Perform integrity verification on decrypt_response.
        # For more details on ensuring E2E in-transit integrity to and
        # from Cloud KMS visit:
        # https://cloud.google.com/kms/docs/data-integrity-guidelines
        if not decrypt_response.plaintext_crc32c == self._crc32c(
                decrypt_response.plaintext):
            eh.add_dev_error(
                'GoogleEncryptor',
                "The response received from google when decrypting the "
                "data was corrupted in-transit.")

        return decrypt_response

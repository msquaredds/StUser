import base64
import os.path
import smtplib

from email.message import EmailMessage
from google.appengine.api import mail
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from typing import Union


class Email(object):
    """
    Create and send emails of different types with different services.

    TODO:
        - Get smtp_email_registered_user to work or remove it.
        - Test app_engine_email_registered_user on Google App Engine.
    """
    def __init__(self, email: str, username: str = None,
                 website_name: str = None, website_email: str = None) -> None:
        """
        :param email: The email of the user.
        :param username: The username of the user.
        :param website_name: The name of the website that is using this
            package.
        :param website_email: The email address that is sending the email.
        """
        self.email = email
        self.username = username
        self.website_name = website_name
        self.website_email = website_email

    def get_gmail_oauth2_credentials(
            self, secrets_dict: str,
            token_file_name: str = 'token.json') -> Credentials:
        """
        Get the credentials for the Gmail API using the OAuth2 flow.

        :param secrets_dict: This can either be the dictionary of the
            client secrets or the path to the client secrets file in JSON.
            Note that putting the secrets file in the same directory as
            the script is not secure. The function here that uses the
            data: from_client_secrets_file, is meant to be used with a
            file path, but the dictionary seems to work as well. If this
            breaks, try using the alternate method: from_client_config.
            https://google-auth-oauthlib.readthedocs.io/en/latest/reference/google_auth_oauthlib.flow.html
        :param token_file_name: The name of the file to store the token.
        :return creds: The credentials for the Gmail API.
        """
        scopes = ['https://www.googleapis.com/auth/gmail.modify']

        creds = None
        # the file token.json stores the user's access and refresh tokens,
        # and is created automatically when the authorization flow
        # completes for the first time
        if os.path.exists(token_file_name):
            creds = Credentials.from_authorized_user_file(
                token_file_name, scopes)
        # if there are no (valid) credentials available, let the user log
        # in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_config(
                    secrets_dict, scopes)
                creds = flow.run_local_server(port=0)
                # Save the credentials for the next run
                with open(token_file_name, "w") as token:
                    token.write(creds.to_json())
        return creds

    def gmail_email_registered_user(
            self, creds: Credentials) -> Union[None, str]:
        """
        Gmail method to email the registered user to let them know they've
        registered. Must be used with a Gmail account.

        For now, we pass the credentials into this function.

        The only testing that has been done was using the Google OAuth2
        flow. This requires enabling the gmail API, consenting to OAuth2
        and allowing external users with the desired "from" email address
        as an authorized user, and creating credentials to use to connect
        to the gmail API. See the following links for more information:
        https://developers.google.com/gmail/api/quickstart/python#step_3_set_up_the_sample
        https://developers.google.com/gmail/api/guides/sending
        Note that the credentials are stored in a file called "token.json"
        and the first time this is run, the user will be prompted to
        consent to the OAuth2 flow. After that, the token will be stored
        and the user will not be prompted again, but if the token expires,
        the user will be prompted again. This is not a real problem for a
        developer with access to the gmail account, but would be a problem
        for an end user.

        In the future, we may want to test using a service account through
        Google Workspace (formerly G Suite) that has delegated authority
        to send emails on behalf of another account. This has not been
        tested, but if it works, the service account and OAuth methods
        could be moved into this method with options for gathering either
        set of credentials.
        See here for more details on the service accounts:
        https://github.com/GoogleCloudPlatform/professional-services/tree/main/examples/gce-to-adminsdk
        https://stackoverflow.com/questions/62846906/httperror-400-precondition-check-failed-during-users-messages-list-gmail-api

        :param creds: The credentials for the Gmail API.
        """
        try:
            # Call the Gmail API
            service = build("gmail", "v1", credentials=creds)

            message = EmailMessage()

            message.set_content(
                f"""Thank you for registering for {self.website_name}!\n
                You have successfully registered with the username: 
                {self.username}.\n
                If you did not register or you have any questions,
                please contact us at {self.website_email}.""")

            message["To"] = self.email
            message["From"] = self.website_email
            message["Subject"] = (f'{self.website_name}: Thank You for '
                                  f'Registering')

            # encoded message
            encoded_message = base64.urlsafe_b64encode(
                message.as_bytes()).decode()

            create_message = {"raw": encoded_message}
            # pylint: disable=E1101
            send_message = (
                service.users()
                .messages()
                .send(userId="me", body=create_message)
                .execute()
            )
            return None

        except HttpError as error:
            return error

    def smtp_email_registered_user(self) -> None:
        """
        DOES NOT WORK

        Generic (SMTP) way to email the registered user to let them know
        they've registered.
        """
        msg = EmailMessage()
        msg['Subject'] = f'{self.website_name}: Thank You for Registering'
        msg['From'] = self.website_email
        msg['To'] = self.email
        msg.set_content(
            f"""Thank you for registering for {self.website_name}!\n
            You have successfully registered with the username: 
            {self.username}.\n
            If you did not register or you have any questions,
            please contact us at {self.website_email}.""")

        # Send the message via our own SMTP server.
        s = smtplib.SMTP(port=587)
        # tried with SMTP('localhost') and SMTP(port=587)
        # tried s.starttls(), s.ehlo() and s.connect(), adding one by one
        # in that order
        s.connect()
        s.starttls()
        s.ehlo()
        s.send_message(msg)
        s.quit()

    def app_engine_email_registered_user(self) -> None:
        """
        NEEDS TO BE TESTED ON APP ENGINE

        Google App Engine way to email the registered user to let them
        know they've registered. Must be used with an app hosted on
        Google App Engine.

        https://cloud.google.com/appengine/docs/standard/python3/services/mail
        """
        msg = mail.EmailMessage()
        msg.subject = f'{self.website_name}: Thank You for Registering'
        msg.sender = self.website_email
        msg.to = self.email
        msg.body = (
            f"""Thank you for registering for {self.website_name}!\n
            You have successfully registered with the username:
            {self.username}.\n
            If you did not register or you have any questions,
            please contact us at {self.website_email}.""")
        msg.send()

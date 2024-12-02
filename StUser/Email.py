import base64
import os.path

from email.message import EmailMessage
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from typing import Union


class Email(object):
    """
    Create and send emails with different services.
    """
    def __init__(self, email: str, subject: str, body: str,
                 website_email: str = None) -> None:
        """
        :param email: The email of the user.
        :param subject: The subject of the email.
        :param body: The body of the email.
        :param website_email: The email address that is sending the email.
        """
        self.email = email
        self.subject = subject
        self.body = body
        self.website_email = website_email

    def get_gmail_oauth2_credentials(
            self, secrets_dict: str,
            token_file_name: str = 'token.json') -> Credentials:
        """
        Get the credentials for the Gmail API using the OAuth2 flow.

        Note that this only works for local / desktop apps.

        :param secrets_dict: The dictionary of the client secrets.
            Note that putting the secrets in the same directory as
            the script is not secure.
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

        Note that this only works for local / desktop apps.

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

            message.set_content(self.body)

            message["To"] = self.email
            message["From"] = self.website_email
            message["Subject"] = self.subject

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

    def sendgrid_email_registered_user(
            self, sendgrid_api_key: str) -> Union[None, str]:
        """
        SendGrid method to email the registered user to let them know
        they've registered. Must be used with a SendGrid account.

        For now, we pass the API key into this function. It can be stored
        separately in a secure location, such as a Google Cloud Datastore
        or encrypted in your project's pyproject.toml file.

        :param sendgrid_api_key: The API key for the SendGrid account.
        """
        message = Mail(
            from_email=self.website_email,
            to_emails=self.email,
            subject=self.subject,
            html_content=self.body)

        try:
            sg = SendGridAPIClient(sendgrid_api_key)
            response = sg.send(message)

            response_status_code = str(response.status_code)
            response_body = str(response.body)

            if response_status_code[0] in ["4", "5"]:
                # statuses 400 and 500 are errors
                # see: https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes
                return f"{response_status_code}: {response_body}"

        except Exception as error:
            return str(error)

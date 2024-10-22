import streamlit as st

from typing import Union

from StreamlitAuth.Email import Email
from StreamlitAuth.Validator import Validator


class Verification(object):
    """
    Used for verification that happens outside of the main forms in
    Authenticate.py.

    Unlike in Authenticate, we just raise errors here so they can be
    handled in any way the user likes, since these may not be run in a
    Streamlit app.
    """
    def __init__(self) -> None:
        if 'stauth' not in st.session_state:
            st.session_state['stauth'] = {}

    def _add_emails_codes(
            self, code_store_args: dict, auth_codes: dict) -> dict:
        if code_store_args is None:
            code_store_args = {}
        # change auth codes from {email1: code1, email:2: code2} to
        # {'emails': [emails], 'codes': [codes]}
        emails_codes = {'emails': list(auth_codes.keys()),
                        'codes': list(auth_codes.values())}
        code_store_args['emails_codes'] = emails_codes
        return code_store_args

    def _rename_code_store_args(self, code_store_args: dict) -> dict:
        """Update the column names."""
        emails_codes = code_store_args['emails_codes']
        emails_codes = {code_store_args['email_col']: emails_codes['emails'],
                        code_store_args['code_col']: emails_codes['codes']}
        code_store_args['emails_codes'] = emails_codes
        del code_store_args['email_col']
        del code_store_args['code_col']
        return code_store_args

    def _update_auth_codes(
            self,
            code_store_function: Union[Callable, str],
            code_store_args: dict,
            auth_codes: dict) -> None:
        """Update authorization codes for the given emails."""
        code_store_args = self._add_emails_codes(
            code_store_args, auth_codes)
        if isinstance(code_store_function, str):
            if code_store_function.lower() == 'bigquery':
                # update the code_store_args to the correct
                # variable names
                code_store_args = self._rename_code_store_args(
                    code_store_args)
                db = BQTools()
                error = db.store_preauthorization_codes(**code_store_args)
                if error is not None:
                    raise RuntimeError(error)
            else:
                raise ValueError(
                    "The code_store_function method is not recognized. "
                    "The available options are: 'bigquery' or a "
                    "callable function.")
        else:
            error = code_store_function(**code_store_args)
            if error is not None:
                raise RuntimeError(error)

    def _send_user_email(
            self,
            auth_codes: dict,
            email_inputs: dict,
            email_user: Union[callable, str],
            email_creds: dict = None) -> None:
        """
        Send an email to the user with their authorization code.

        :param auth_codes: The authorization code(s) for the user(s).
            {email1: code1, email2: code2}
        :param email_inputs: The inputs for the email sending process.
            These are generic for any email method and currently include:

            website_name (str): The name of the website where the
                registration is happening.
            website_email (str) : The email that is sending the
                registration confirmation.
        :param email_user: Provide the function (callable) or method (str)
            for email here.
            "gmail": the user wants to use their Gmail account to send
                the email and must have the gmail API enabled. Note that
                this only works for local / desktop apps. If using this
                method, you must supply the
                oauth2_credentials_secrets_dict variable and
                optionally the oauth2_credentials_token_file_name
                variable, as parts of the gmail_creds input.
                https://developers.google.com/gmail/api/guides
            "sendgrid": the user wants to use the SendGrid API to send
                the email. Note that you must have signed up for a
                SendGrid account and have an API key. If using this
                method, you must supply the API key as the sendgrid_creds
                input here.
        :param email_creds: The credentials to use for the email API. See
            the docstring for preauthorization_code for more information.
        """
        subject = f"{email_inputs['website_name']}: Preauthorization Code"
        for email, code in auth_codes.items():
            body = (f"Your authorization code is: {code} \n\n"
                    f"If you did not request this code or your code is not "
                    f"working as expected, please contact us immediately at "
                    f"{email_inputs['website_email']}.")
            email_handler = Email(email, subject, body, **email_inputs)
            if isinstance(email_user, str):
                if email_user.lower() == 'gmail':
                    creds = email_handler.get_gmail_oauth2_credentials(
                        **email_creds)
                    error = email_handler.gmail_email_registered_user(creds)
                elif email_user.lower() == 'sendgrid':
                    error = email_handler.sendgrid_email_registered_user(
                        **email_creds)
                else:
                    raise ValueError(
                        "The email_user method is not recognized. "
                        "The available options are: 'gmail' or 'sendgrid'.")
            else:
                error = email_user(**email_creds)
            if error is not None:
                raise RuntimeError(error)

    def preauthorization_code(
            self,
            email: Union[str, list],
            code_store_function: Union[str, Callable] = None,
            code_store_args: dict = None,
            email_user: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None) -> None:
        """
        Creates a preauthorization code and optionally saves it to a
        database and emails it to the user.

        :param email: The email address(es) to create the preauthorization
            code(s) for and where to send the email, if desired.
        :param code_store_function: The function to store the new
            authorization code associated with the email. This can be a
            callable function or a string.

            At a minimum, a callable function should take 'code' as
            an argument.
            A callable function can return an error message.

            The current pre-defined function types are:
                'bigquery': Saves the credentials to a BigQuery table.

            This is only necessary if you want to save the code to
            a database or other storage location. This can be useful so
            that you can confirm the code is saved during the
            callback and handle that as necessary.
        :param code_store_args: Arguments for the code_store_function.
            This should not include 'email' as that will automatically be
            added here based on the input variable. Instead, it should
            include things like database name, table name, credentials to
            log into the database, etc. That way they can be compiled in
            this function and passed to the function in the callback.

            If using 'bigquery' as your code_store_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            email_col (str): The name of the column in the BigQuery
                table that contains the emails.
            code_col (str): The name of the column in the BigQuery
                table that contains the authorization codes.
        :param email_user:  Provide the method for email here, this can be
            a callable function or a string. The function can also return
            an error message as a string, which will be handled by the
            error handler.

            The current pre-defined function types are:

            "gmail": the user wants to use their Gmail account to send
                the email and must have the gmail API enabled. Note that
                this only works for local / desktop apps. If using this
                method, you must supply the
                oauth2_credentials_secrets_dict variable and
                optionally the oauth2_credentials_token_file_name
                variable, as parts of the gmail_creds input.
                https://developers.google.com/gmail/api/guides
            "sendgrid": the user wants to use the SendGrid API to send
                the email. Note that you must have signed up for a
                SendGrid account and have an API key. If using this
                method, you must supply the API key as the sendgrid_creds
                input here.
        :param email_inputs: The inputs for the email sending process.
            These are generic for any email method and currently include:

            website_name (str): The name of the website where the
                registration is happening.
            website_email (str) : The email that is sending the
                registration confirmation.
        :param email_creds: The credentials to use for the email API. Only
            necessary if email_user is not None.

            If email_user = 'gmail':
                oauth2_credentials_secrets_dict (dict): The dictionary of
                    the client secrets. Note that putting the secrets file
                    in the same directory as the script is not secure.
                oauth2_credentials_token_file_name (str): Optional. The
                    name of the file to store the token, so it is not
                    necessary to reauthenticate every time. If left out,
                    it will default to 'token.json'.
            If email_user = 'sendgrid':
                sendgrid_api_key (str): The API key for the SendGrid API.
                    Note that it should be stored separately in a secure
                    location, such as a Google Cloud Datastore or
                    encrypted in your project's pyproject.toml file.

                    Example code to get the credentials in Google Cloud
                        DataStore (you must install google-cloud-datastore
                        in your environment):
                        from google.cloud import datastore
                        # you can also specify the project and/or database
                        # in Client() below
                        # you might also need credentials to connect to
                        # the client if not run on Google App Engine (or
                        # another service that recognizes the credentials
                        # automatically)
                        client = datastore.Client()
                        # replace "apikeys" with the kind you set up in
                        # datastore
                        docs = list(client.query(kind="apikeys").fetch())
                        # replace "sendgridapikey" with the name of the
                        # key you set up in datastore
                        api_key = docs[0]["sendgridapikey"]
            Otherwise, these must be defined by the user in the callable
            function and will likely include credentials to the email
            service.
        """
        if isinstance(email, str):
            email = [email]
        auth_codes = {}
        validator = Validator()
        for e in email:
            auth_codes[e] = validator.generate_random_password()
        st.session_state.stauth['auth_codes'] = auth_codes

        if code_store_function is not None:
            self._update_auth_codes(
                code_store_function, code_store_args, auth_codes)
            if email_user is not None:
                self._send_user_email(
                    auth_codes, email_inputs, email_user, email_creds)
        elif email_user is not None:
            self._send_user_email(
                auth_codes, email_inputs, email_user, email_creds)

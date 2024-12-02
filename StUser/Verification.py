import streamlit as st

from typing import Callable, Union

from StUser.BQTools import BQTools
from StUser.Email import Email
from StUser.Hasher import Hasher
from StUser.Validator import Validator


class Verification(object):
    """
    Used for verification that happens outside of the main forms in
    Forms.py.

    Unlike in Forms, we just raise errors here so they can be handled in
    any way the user likes, since these may not be run in a Streamlit app.
    """
    def __init__(self) -> None:
        if 'stuser' not in st.session_state:
            st.session_state['stuser'] = {}

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
            email_function: Union[Callable, str],
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
        :param email_function: Provide the function (callable) or method
            (str) for email here.
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
            body = (f"Your authorization code is: {code} .\n\n"
                    f"If you did not request this code or your code is not "
                    f"working as expected, please contact us immediately at "
                    f"{email_inputs['website_email']}.")
            email_handler = Email(email, subject, body,
                                  email_inputs['website_email'])
            if isinstance(email_function, str):
                if email_function.lower() == 'gmail':
                    creds = email_handler.get_gmail_oauth2_credentials(
                        **email_creds)
                    error = email_handler.gmail_email_registered_user(creds)
                elif email_function.lower() == 'sendgrid':
                    error = email_handler.sendgrid_email_registered_user(
                        **email_creds)
                else:
                    raise ValueError(
                        "The email_function method is not recognized. "
                        "The available options are: 'gmail' or 'sendgrid'.")
            else:
                error = email_function(**email_creds)
            if error is not None:
                raise RuntimeError(error)

    def preauthorization_code(
            self,
            email: Union[str, list],
            code_store_function: Union[str, Callable] = None,
            code_store_args: dict = None,
            email_function: Union[Callable, str] = None,
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
        :param email_function:  Provide the method for email here, this
            can be a callable function or a string. The function can also
            return an error message as a string, which will be handled by
            the error handler.

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
            necessary if email_function is not None.

            If email_function = 'gmail':
                oauth2_credentials_secrets_dict (dict): The dictionary of
                    the client secrets. Note that putting the secrets file
                    in the same directory as the script is not secure.
                oauth2_credentials_token_file_name (str): Optional. The
                    name of the file to store the token, so it is not
                    necessary to reauthenticate every time. If left out,
                    it will default to 'token.json'.
            If email_function = 'sendgrid':
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
        st.session_state.stuser['auth_codes'] = auth_codes

        if code_store_function is not None:
            # we pass the hashed authorization codes for storage so they
            # are more secure
            hashed_auth_codes = {
                email: Hasher([password]).generate()[0]
                for email, password in auth_codes.items()}
            self._update_auth_codes(
                code_store_function, code_store_args, hashed_auth_codes)
            if email_function is not None:
                self._send_user_email(
                    auth_codes, email_inputs, email_function, email_creds)
        elif email_function is not None:
            self._send_user_email(
                auth_codes, email_inputs, email_function, email_creds)

    def _add_email_to_args(
            self, email: str, existing_args: dict) -> dict:
        """Add the email to existing_args."""
        if existing_args is None:
            existing_args = {}
        existing_args['email'] = email
        return existing_args

    def _rename_email_code_pull_args(self, email_code_pull_args: dict) -> dict:
        """Update the target and reference columns and reference value."""
        email_code_pull_args['reference_col'] = email_code_pull_args[
            'email_col']
        email_code_pull_args['reference_value'] = email_code_pull_args[
            'email']
        email_code_pull_args['target_col'] = email_code_pull_args[
            'email_code_col']
        del email_code_pull_args['email_col']
        del email_code_pull_args['email']
        del email_code_pull_args['email_code_col']
        return email_code_pull_args

    def _check_email_code(
            self,
            email_address: str,
            email_code: str,
            email_code_pull_function: Union[str, Callable],
            email_code_pull_args: dict = None) -> bool:
        """
        Pulls the expected email code and checks the validity of the input
        email code.

        :param email_address: The pulled email address.
        :param email_code: The pulled email code.
        :param email_code_pull_function: The function to pull the hashed
            email code associated with the email. This can be a
            callable function or a string.

            At a minimum, a callable function should take 'email_address'
            as an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error'
                or 'success'.
             - The value should be a string that contains the error
                message when the indicator is 'dev_error', None when the
                indicator is 'user_error', and the hashed email
                code when the indicator is 'success'. It is None with
                'user_error' since we will handle that in the calling
                function and create a user_error that tells the user that
                the email or authorization code is incorrect.

            The current pre-defined function types are:
                'bigquery': Pulls the email code from a BigQuery table.
        :param email_code_pull_args: Arguments for the
            email_code_pull_function. This should not include
            'email_address' since that will automatically be added here
            based on the input.

            If using 'bigquery' as your email_code_pull_function, the
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
            email_code_col (str): The name of the column in the BigQuery
                table that contains the email codes.
        """
        # add the email to the arguments for the email code pull function
        email_code_pull_args = self._add_email_to_args(
            email_address, email_code_pull_args)
        # pull the email code
        if isinstance(email_code_pull_function, str):
            if email_code_pull_function.lower() == 'bigquery':
                email_code_pull_args = self._rename_email_code_pull_args(
                    email_code_pull_args)
                db = BQTools()
                indicator, value = db.pull_value_based_on_other_col_value(
                    **email_code_pull_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The email_code_pull_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = email_code_pull_function(**email_code_pull_args)

        # only continue if we didn't have any issues getting the email
        # code
        if indicator not in ('dev_error', 'user_error'):
            verified = Hasher([email_code]).check([value])[0]
            # we can have errors here if the email code doesn't
            # match or there is an issue running the check
            if verified == 'dev_error':
                raise RuntimeError(
                    "There was an error verifying the email code. Please "
                    "contact the administrator.")
            elif verified:
                return True
            else:
                return False
        else:
            raise RuntimeError(value)

    def _add_inputs_email_verification_update(
            self, verified_store_args: dict, email: str,
            verified: bool) -> dict:
        if verified_store_args is None:
            verified_store_args = {}
        # add the inputs to verified_store_args
        verified_store_args['email'] = email
        verified_store_args['verified'] = verified
        return verified_store_args

    def _rename_email_verification_store_args(
            self, verified_store_args: dict) -> dict:
        """Update the target and reference columns and reference value."""
        verified_store_args['reference_col'] = verified_store_args[
            'email_col']
        verified_store_args['reference_value'] = verified_store_args[
            'email']
        verified_store_args['target_col'] = verified_store_args['verified_col']
        verified_store_args['target_value'] = verified_store_args['verified']
        del verified_store_args['email_col']
        del verified_store_args['email']
        del verified_store_args['verified_col']
        del verified_store_args['verified']
        return verified_store_args

    def _update_email_verification(
            self,
            verified_store_function: Union[Callable, str],
            verified_store_args: dict,
            email: str,
            verified: bool) -> None:
        """Update whether the email is verified for a given email."""
        # first, add the email and verified to the args
        verified_store_args = self._add_inputs_email_verification_update(
            verified_store_args, email, verified)
        if isinstance(verified_store_function, str):
            if verified_store_function.lower() == 'bigquery':
                # update the verified_store_args to the correct variable
                # names
                verified_store_args = (
                    self._rename_email_verification_store_args(
                        verified_store_args))
                db = BQTools()
                error = db.update_value_based_on_other_col_value(
                    **verified_store_args)
            else:
                raise ValueError(
                    "The verified_store_function method is not recognized. "
                    "The available options are: 'bigquery' or a "
                    "callable function.")
        else:
            error = verified_store_function(**verified_store_args)
        if error is not None:
            raise RuntimeError(error)

    def verify_email(self,
                     email_code_pull_function: Union[str, Callable],
                     email_code_pull_args: dict = None,
                     verified_store_function: Union[str, Callable] = None,
                     verified_store_args: dict = None) -> None:
        """
        Pulls the query params from the current URL, checks the email_code
        and optionally stores whether the email has been verified.

        :param email_code_pull_function: The function to pull the hashed
            email code associated with the email. This can be a
            callable function or a string.

            At a minimum, a callable function should take 'email_address'
            as an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error'
                or 'success'.
             - The value should be a string that contains the error
                message when the indicator is 'dev_error', None when the
                indicator is 'user_error', and the hashed email
                code when the indicator is 'success'. It is None with
                'user_error' since we will handle that in the calling
                function and create a user_error that tells the user that
                the email or authorization code is incorrect.

            The current pre-defined function types are:
                'bigquery': Pulls the email code from a BigQuery table.
        :param email_code_pull_args: Arguments for the
            email_code_pull_function. This should not include
            'email_address' since that will automatically be added here
            based on the input.

            If using 'bigquery' as your email_code_pull_function, the
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
            email_code_col (str): The name of the column in the BigQuery
                table that contains the email codes.
        :param verified_store_function: The function to store an indicator
            that the email was verified. This can be a callable function
            or a string.

            At a minimum, a callable function should take 'verified' as
            an argument.
            A callable function can return an error message.

            The current pre-defined function types are:
                'bigquery': Saves the verification to a BigQuery table.

            This is only necessary if you want to save the code to
            a database or other storage location. This can be useful so
            that you can confirm the email is verified when logging the
            user in.
        :param verified_store_args: Arguments for the
            verified_store_function. This should not include 'verified' as
            that will automatically be added here based on the result of
            checking the email code. Instead, it should include things
            like database name, table name, credentials to log into the
            database, etc. That way they can be compiled in this function
            and passed to the function in the callback.

            If using 'bigquery' as your verified_store_function, the
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
            verified_col (str): The name of the column in the BigQuery
                table that contains the verification indicator.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime. This is used to track
                when the verification was updated.
        """
        try:
            email_address = st.query_params['email_address']
            email_code = st.query_params['email_code']
        except KeyError:
            raise KeyError("The email_address or email_code parameter is "
                           "missing.")

        # check the code
        if self._check_email_code(
                email_address, email_code, email_code_pull_function,
                email_code_pull_args):
            st.session_state.stuser['email_verified'] = True

            if verified_store_function is not None:
                # store that the verification was successful
                self._update_email_verification(
                    verified_store_function, verified_store_args,
                    email_address, True)
        else:
            st.session_state.stuser['email_verified'] = False

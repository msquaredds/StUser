import pandas as pd
import streamlit as st

from datetime import datetime, timedelta
from typing import Callable, Tuple, Union

from StreamlitAuth import ErrorHandling as eh
from StreamlitAuth.BQTools import BQTools
from StreamlitAuth.Email import Email
from StreamlitAuth.Encryptor import GenericEncryptor, GoogleEncryptor
from StreamlitAuth.Hasher import Hasher


class Authenticate(object):
    """
    Create register user, login, forgot password, forgot username,
    reset password, reset username and logout methods/widgets.

    :method register_user: Creates a new user registration widget.
    """
    def __init__(self,
                 usernames_session_state: str,
                 emails_session_state: str,
                 user_credentials_session_state: str,
                 preauthorized_session_state: str = None,
                 weak_passwords: list = []) -> None:
        """
        :param usernames_session_state: The session state name to access
            the LIST of existing usernames (st.session_state[
            usernames_session_state]). These should be saved into the
            session state before instantiating this class. We use session
            state since we want to be able to update the list of usernames
            with the methods of this class and want the updated list to
            persist.
        :param emails_session_state: The session state name to access the
            LIST of existing emails (st.session_state[
            emails_session_state]). These should be saved into the session
            state before instantiating this class. We use session state
            since we want to be able to update the list of emails
            with the methods of this class and want the updated list to
            persist.
        :param user_credentials_session_state: The session state name to
            access the DICTIONARY of user credentials as
            {'username': username, 'email': email, 'password': password},
            with username and email encrypted and password hashed
            (st.session_state[user_credentials_session_state]). These
            are defined within the methods of this class and do not need
            to be saved into the session state before instantiating this
            class. We use session state since we want to be able to update
            the dictionary of user credentials with the methods of this
            class and want the updated dictionary to persist.
        :param preauthorized_session_state: The session state name to
            access the LIST of emails of unregistered users authorized to
            register (st.session_state[preauthorized_session_state]).
            These should be saved into the session state before
            instantiating this class. We use session state since we want
            to be able to update the list of emails with the methods of
            this class and want the updated list to persist.
        :param weak_passwords: The list of weak passwords that shouldn't
            be used. This isn't required, but is recommended.
        """
        self.usernames_session_state = usernames_session_state
        self.emails_session_state = emails_session_state
        self.user_credentials_session_state = user_credentials_session_state
        self.preauthorized_session_state = preauthorized_session_state
        self.weak_passwords = weak_passwords

        if 'stauth' not in st.session_state:
            st.session_state['stauth'] = {}
        if 'authentication_status' not in st.session_state.stauth:
            st.session_state.stauth['authentication_status'] = False
        if 'username' not in st.session_state.stauth:
            st.session_state.stauth['username'] = None
        if 'logout' not in st.session_state.stauth:
            st.session_state.stauth['logout'] = False

    def _check_register_user_session_states(
            self, preauthorization: bool) -> bool:
        """
        Check on whether all session state inputs for register_user exist
        and are the correct type.
        """
        if self.usernames_session_state not in st.session_state or \
                not isinstance(st.session_state[self.usernames_session_state],
                               (list, set)):
            eh.add_dev_error(
                'register_user',
                "usernames_session_state must be a list or set "
                "assigned to st.session_state[usernames_session_state]")
            return False
        if self.emails_session_state not in st.session_state or \
                not isinstance(st.session_state[self.emails_session_state],
                               (list, set)):
            eh.add_dev_error(
                'register_user',
                "emails_session_state must be a list or set assigned to "
                "st.session_state[emails_session_state]")
            return False
        if preauthorization:
            if self.preauthorized_session_state not in st.session_state or \
                    not isinstance(st.session_state[
                                       self.preauthorized_session_state],
                                   (list, set)):
                eh.add_dev_error(
                    'register_user',
                    "preauthorized_session_state must be a list or set "
                    "assigned to st.session_state["
                    "preauthorized_session_state]")
                return False
        return True

    def _check_register_user_inputs(self, location: str) -> bool:
        """
        Check whether the register_user inputs are within the correct set
        of options.
        """
        if location not in ['main', 'sidebar']:
            eh.add_dev_error(
                'register_user',
                "location argument must be one of 'main' or 'sidebar'")
            return False
        return True

    def _check_register_user_info(
            self, new_email: str, new_username: str, new_password: str,
            new_password_repeat: str, preauthorization: bool) -> bool:
        """
        Check whether the registering user input is valid.

        :param new_email: The new user's email.
        :param new_username: The new user's username.
        :param new_password: The new user's password.
        :param new_password_repeat: The new user's repeated password.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        """
        validator = Validator()
        # all fields must be filled
        if not (len(new_email) > 0 and len(new_username) > 0 and
                len(new_password) > 0):
            eh.add_user_error(
                'register_user',
                "Please enter an email, username and password.")
            return False
        # the email must not already be used
        if new_email in st.session_state[self.emails_session_state]:
            eh.add_user_error(
                'register_user',
                "Email already taken, please use forgot username if this is "
                "your email.")
            return False
        # the email must be of correct format
        if not validator.validate_email(new_email):
            eh.add_user_error(
                'register_user',
                "Email is not a valid format.")
            return False
        # the username must not already be used
        if new_username in st.session_state[self.usernames_session_state]:
            eh.add_user_error(
                'register_user',
                "Username already taken.")
            return False
        # the username must be of correct format
        if not validator.validate_username(new_username):
            eh.add_user_error(
                'register_user',
                "Username must only include letters, numbers, '-' or '_' "
                "and be between 1 and 20 characters long.")
            return False
        # the password must be secure enough
        if not validator.validate_password(new_password, self.weak_passwords):
            eh.add_user_error(
                'register_user',
                "Password must be between 8 and 64 characters, contain at "
                "least one uppercase letter, one lowercase letter, one "
                "number, and one special character.")
            return False
        # the password must be repeated correctly
        if new_password != new_password_repeat:
            eh.add_user_error(
                'register_user',
                "Passwords do not match.")
            return False
        # the user must be preauthorized if preauthorization is True
        if preauthorization and new_email not in st.session_state[
                self.preauthorized_session_state]:
            eh.add_user_error(
                'register_user',
                "User not preauthorized to register.")
            return False
        return True

    def _register_credentials(self, username: str, password: str,
                              email: str, preauthorization: bool) -> None:
        """
        Adds to credentials dictionary the new user's information.

        :param username: The username of the new user.
        :param password: The password of the new user.
        :param email: The email of the new user.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        """
        # we want to add our new username and email to the session state,
        # so they can't be accidentally registered again
        st.session_state[self.usernames_session_state].append(username)
        st.session_state[self.emails_session_state].append(email)

        # hash password
        password = Hasher([password]).generate()[0]

        # store the credentials
        st.session_state[self.user_credentials_session_state] = {
            'username': username,
            'email': email,
            'password': password}

        # if we had the name preauthorized, remove it from that list
        if preauthorization:
            st.session_state[self.preauthorized_session_state].remove(email)

    def _add_user_credentials_to_save_function(
            self, cred_save_args: dict) -> dict:
        if cred_save_args is None:
            cred_save_args = {}
        # add the user_credentials to cred_save_args
        cred_save_args['user_credentials'] = st.session_state[
            self.user_credentials_session_state].copy()
        return cred_save_args

    def _save_user_credentials(self, cred_save_function: Union[Callable, str],
                               cred_save_args: dict) -> Union[None, str]:
        """Save user credentials."""
        # first, add the user credentials to the cred_save_args
        cred_save_args = self._add_user_credentials_to_save_function(
            cred_save_args)
        if isinstance(cred_save_function, str):
            if cred_save_function.lower() == 'bigquery':
                db = BQTools()
                error = db.store_user_credentials(**cred_save_args)
            else:
                error = ("The cred_save_function method is not recognized. "
                         "The available options are: 'bigquery' or a "
                         "callable function.")
        else:
            error = cred_save_function(**cred_save_args)
        return error

    def _cred_save_error_handler(self, error: str) -> bool:
        """
        Records any errors from the credential saving process.
        """
        if error is not None:
            eh.add_dev_error(
                'register_user',
                "There was an error saving the user credentials. "
                "Error: " + error)
            return False
        return True

    def _check_email_inputs(self, website_name: str = None,
                            website_email: str = None) -> bool:
        """
        Check on whether the inputs for emails exist and are the correct
        type.
        """
        validator = Validator()
        # website_name must be a string
        if not isinstance(website_name, str):
            eh.add_dev_error(
                'register_user',
                "website_name must be a string.")
            return False
        # the email must be of correct format
        if not isinstance(website_email, str) or \
                not validator.validate_email(website_email):
            eh.add_dev_error(
                'register_user',
                "website_email is not a valid format.")
            return False
        return True

    def _email_error_handler(self, error: str) -> bool:
        """
        Records any errors from the email sending process.
        """
        if error is not None:
            eh.add_dev_error(
                'register_user',
                "There was an error sending the confirmation email. "
                "Error: " + error)
            return False
        return True

    def _send_register_user_email(
            self, new_email: str, new_username: str,
            email_inputs: dict, email_user: Union[callable, str],
            email_creds: dict = None) -> None:
        """
        Send a confirmation email to the newly registered user.

        :param new_email: The new user's email.
        :param new_username: The new user's username.
        :param email_inputs: The inputs for the email sending process.
            Only necessary for when email_user is not None.
            These are generic for any email method and currently include:

            website_name (str): The name of the website where the
                registration is happening.
            website_email (str) : The email that is sending the
                registration confirmation.
        :param email_user: If we want to email the user after registering,
            provide the function (callable) or method (str) for email
            here. See the docstring for register_user for more
            information.
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
        :param email_creds: The credentials to use for the email API. Only
            necessary if email_user is not None. See the
            docstring for register_user for more information.
        """
        email_handler = Email(new_email, new_username, **email_inputs)
        if self._check_email_inputs(**email_inputs):
            if isinstance(email_user, str):
                if email_user.lower() == 'gmail':
                    creds = email_handler.get_gmail_oauth2_credentials(
                        **email_creds)
                    error = email_handler.gmail_email_registered_user(creds)
                elif email_user.lower() == 'sendgrid':
                    error = email_handler.sendgrid_email_registered_user(
                        **email_creds)
                else:
                    error = ("The email_user method is not recognized. "
                             "The available options are: 'gmail' or "
                             "'sendgrid'.")
            else:
                error = email_user(**email_creds)
            if self._email_error_handler(error):
                eh.clear_errors()

    def _check_and_register_user(
            self,
            email_text_key: str,
            username_text_key: str,
            password_text_key: str,
            repeat_password_text_key: str,
            preauthorization: bool,
            email_user: Union[callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None,
            cred_save_function: Union[Callable, str] = None,
            cred_save_args: dict = None) -> None:
        """
        Once a new user submits their info, this is a callback to check
        the validity of their input and register them if valid.

        :param email_text_key: The session state name to access the new
            user's email.
        :param username_text_key: The session state name to access the new
            user's username.
        :param password_text_key: The session state name to access the new
            user's password.
        :param repeat_password_text_key: The session state name to access
            the new user's repeated password.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param email_user: If we want to email the user after registering,
            provide the function (callable) or method (str) for email
            here.  See the docstring for register_user for more
            information.
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
            Only necessary for when email_user is not None. See the
            docstring for register_user for more information.
        :param email_creds: The credentials to use for the email API. Only
            necessary if email_user is not None. See the
            docstring for register_user for more information.
        :param cred_save_function: The function to save the credentials.
            See the docstring for register_user for more information.
        :param cred_save_args: The arguments to pass to the
            cred_save_function. Only necessary if cred_save_function is
            not none. See the docstring for register_user for more
            information.
        """
        new_email = st.session_state[email_text_key]
        new_username = st.session_state[username_text_key]
        new_password = st.session_state[password_text_key]
        new_password_repeat = st.session_state[repeat_password_text_key]
        if self._check_register_user_info(
                new_email, new_username, new_password, new_password_repeat,
                preauthorization):
            self._register_credentials(
                new_username, new_password, new_email, preauthorization)
            # we can either try to save credentials and email, save
            # credentials and not email, just email, or none of the above
            if cred_save_function is not None:
                error = self._save_user_credentials(
                    cred_save_function, cred_save_args)
                if self._cred_save_error_handler(error):
                    if email_user is not None:
                        self._send_register_user_email(
                            new_email, new_username, email_inputs, email_user,
                            email_creds)
                    else:
                        eh.clear_errors()
            elif email_user is not None:
                self._send_register_user_email(
                    new_email, new_username, email_inputs, email_user,
                    email_creds)
            else:
                # get rid of any errors, since we have successfully
                # registered
                eh.clear_errors()

    def register_user(self,
                      location: str = 'main',
                      preauthorization: bool = False,
                      email_text_key: str = 'register_user_email',
                      username_text_key: str = 'register_user_username',
                      password_text_key: str = 'register_user_password',
                      repeat_password_text_key: str =
                          'register_user_repeat_password',
                      email_user: Union[Callable, str] = None,
                      email_inputs: dict = None,
                      email_creds: dict = None,
                      cred_save_function: Union[Callable, str] = None,
                      cred_save_args: dict = None) -> None:
        """
        Creates a new user registration widget.

        :param location: The location of the register new user form i.e.
            main or sidebar.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param email_text_key: The key for the email text input on the
            registration form. We attempt to default to a unique key, but
            you can put your own in here if you want to customize it or
            have clashes with other keys/forms.
        :param username_text_key: The key for the username text input on
            the registration form. We attempt to default to a unique key,
            but you can put your own in here if you want to customize it
            or have clashes with other keys/forms.
        :param password_text_key: The key for the password text input on
            the registration form. We attempt to default to a unique key,
            but you can put your own in here if you want to customize it
            or have clashes with other keys/forms.
        :param repeat_password_text_key: The key for the repeat password
            text input on the registration form. We attempt to default to
            a unique key, but you can put your own in here if you want to
            customize it or have clashes with other keys/forms.
        :param email_user: If we want to email the user after registering,
            provide the method for email here, this can be a callable
            function or a string. The function can also return an error
            message as a string, which will be handled by the error
            handler.

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
            Only necessary for when email_user is not None.
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
        :param cred_save_function: A function (callable) or pre-defined
            function type (str) to save the credentials.

            The current pre-defined function types are:
                'bigquery': Saves the credentials to a BigQuery table.

            This is only necessary if you want to save the credentials to
            a database or other storage location. This can be useful so
            that you can confirm the credentials are saved during the
            callback and handle that as necessary. The function should
            take the user credentials as an argument and save them to the
            desired location. However, those user credentials should not
            be defined in the cred_save_args (see below), since they will
            be created and automatically added here. Instead, it should
            take things like database name, table name, credentials to log
            into the database, etc. The function can also return an error
            message as a string, which will be handled by the error
            handler.
        :param cred_save_args: Arguments for the cred_save_function. Only
            necessary if cred_save_function is not None. Note that these
            arguments should NOT include the user credentials themselves,
            as these will be passed to the function automatically.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc. That way they
            can be compiled in this function and passed to the function in
            the callback. The variable for the cred_save_function for the
            user credentials should be called 'user_credentials'.

            If using 'bigquery' as your cred_save_function, the following
            arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located. This should already exist in
                GCP and have the BigQuery API enabled.
            dataset (str): The name of the dataset in the BigQuery table.
                This should already have been created in BigQuery.
            table_name (str): The name of the table in the BigQuery
                dataset. This does not need to have been created yet in
                the project/dataset. If not, a new table will be created;
                if so, it will be appended to.
        """
        # check on whether all session state inputs exist and are the
        # correct type and whether the inputs are within the correct set
        # of options
        if not self._check_register_user_session_states(preauthorization) or \
                not self._check_register_user_inputs(location):
            return False

        # we need all the usernames to be lowercase
        st.session_state[self.usernames_session_state] = [
            i.lower() for i in st.session_state[self.usernames_session_state]]

        if location == 'main':
            register_user_form = st.form('Register user')
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user')

        register_user_form.subheader('Register user')
        # we need keys for all of these so they can be accessed in the
        # callback through session_state (such as
        # st.session_state['register_user_email'])
        new_email = register_user_form.text_input(
            'Email', key=email_text_key)
        new_username = register_user_form.text_input(
            'Username', key=username_text_key).lower()
        new_password = register_user_form.text_input(
            'Password', type='password', key=password_text_key)
        new_password_repeat = register_user_form.text_input(
            'Repeat password', type='password',
            key=repeat_password_text_key)

        register_user_form.form_submit_button(
            'Register', on_click=self._check_and_register_user,
            args=(email_text_key, username_text_key, password_text_key,
                  repeat_password_text_key, preauthorization, email_user,
                  email_inputs, email_creds, cred_save_function,
                  cred_save_args))

    def check_authentication_status(self) -> bool:
        """Check if the user is authenticated."""
        if ('stauth' in st.session_state and 'authentication_status' in
                st.session_state.stauth and st.session_state.stauth[
                'authentication_status']):
            return True
        else:
            return False

    def _check_login_session_states(self) -> bool:
        """
        Check on whether all session state inputs for login exist and are
        the correct type.
        """
        if self.usernames_session_state not in st.session_state or \
                not isinstance(st.session_state[self.usernames_session_state],
                               (list, set)):
            eh.add_dev_error(
                'login',
                "usernames_session_state must be a list or set "
                "assigned to st.session_state[usernames_session_state]")
            return False
        return True

    def _check_login_inputs(self, location: str) -> bool:
        """
        Check whether the login inputs are within the correct set of
        options.

        :param location: The location of the login form i.e. main or
            sidebar.
        """
        if location not in ['main', 'sidebar']:
            eh.add_dev_error(
                'login',
                "location argument must be one of 'main' or 'sidebar'")
            return False
        return True

    def _check_storage_functions(
            self,
            locked_info_function: Union[str, Callable],
            store_locked_time_function: Union[str, Callable],
            store_unlocked_time_function: Union[str, Callable],
            store_incorrect_attempts_function: Union[str, Callable],
            pull_incorrect_attempts_function: Union[str, Callable]) -> bool:
        """
        Check whether the optional storage functions are all None or all
        not None. Either of those is fine, we just can't have some as None
        and others as not None.
        """
        if (locked_info_function is None and
            store_locked_time_function is None and
            store_unlocked_time_function is None and
            store_incorrect_attempts_function is None and
            pull_incorrect_attempts_function is None) or \
                (locked_info_function is not None and
                 store_locked_time_function is not None and
                 store_unlocked_time_function is not None and
                 store_incorrect_attempts_function is not None and
                 pull_incorrect_attempts_function is not None):
            return True
        eh.add_dev_error(
            'login',
            "If any of the storage functions are used, they must all be "
            "used.")
        return False

    def _check_login_info(
            self, username: str, password: str) -> bool:
        """Check whether the username and password are filled in."""
        if not (len(username) > 0 and len(password) > 0):
            eh.add_user_error(
                'login',
                "Please enter a username and password.")
            return False
        return True

    def _check_username(self, username: str) -> bool:
        """Check if the username is in the list of usernames."""
        if username not in st.session_state[self.usernames_session_state]:
            eh.add_user_error(
                'login',
                "Incorrect username or password.")
            return False
        return True

    def _add_username_to_args(
            self, username: str, existing_args: dict) -> dict:
        """Add the username to existing_args."""
        if existing_args is None:
            existing_args = {}
        existing_args['username'] = username
        return existing_args

    def _pull_locked_unlocked_error_handler(self, indicator: str,
                                            value: str) -> bool:
        """ Records any errors from pulling the latest locked and unlocked
            account times."""
        if indicator == 'dev_error':
            eh.add_dev_error(
                'login',
                "There was an error pulling the latest account lock and "
                "unlock times. "
                "Error: " + value)
            return False
        return True

    def _pull_locked_unlocked_info(
            self,
            username: str,
            locked_info_function: Union[str, Callable],
            locked_info_args: dict) -> Tuple[bool, Union[tuple, None]]:
        """
        Pull the most recent locked and unlocked times from the
        database.

        :param username: The username to check.
        :param locked_info_function: The function to pull the locked
            information associated with the username. This can be a
            callable function or a string.

            The function should pull in locked_info_args, which can be
            used for things like accessing and pulling from a database.
            At a minimum, a callable function should take 'username' as
            one of the locked_info_args, but can include other arguments
            as well.
            A callable function should return:
            - A tuple of an indicator and a value
            - The indicator should be either 'dev_error' or 'success'.
            - The value should be a string that contains the error
                message when the indicator is 'dev_error' and a
                tuple of (latest_lock_datetime, latest_unlock_datetime)
                when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the locked and unlocked datetimes from a
                    BigQuery table.
                    This pre-defined version will look for a table with
                    three columns corresponding to username, locked_time
                    and unlocked_time (see locked_info_args below for how
                    to define there). If the account is locked, the latest
                    locked_time will be more recent than the latest
                    unlocked_time. Note that if using 'bigquery' here,
                    in our other database functions, you should
                    also be using the 'bigquery' option or using your own
                    method that writes to a table set up in the same way.
        :param locked_info_args: Arguments for the locked_info_function.
            This should not include 'username' since that will
            automatically be added here. Instead, it should include things
            like database name, table name, credentials to log into the
            database, etc.

            If using 'bigquery' as your locked_info_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.
            unlocked_time_col (str): The name of the column in the
                BigQuery table that contains the unlocked_times.

        :return: Tuple with the first value as True if the data was pulled
            and False if there was an error, and the second value will be
            a tuple of (latest_lock_datetime, latest_unlock_datetime) if
            the data was pulled successfully, and None if there was an
            error.
        """
        # add the username to the arguments for the locked info
        locked_info_args = self._add_username_to_args(
            username, locked_info_args)
        if isinstance(locked_info_function, str):
            if locked_info_function.lower() == 'bigquery':
                db = BQTools()
                indicator, value = db.pull_locked_info_bigquery(
                    **locked_info_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The locked_info_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = locked_info_function(**locked_info_args)
        if self._pull_locked_unlocked_error_handler(indicator, value):
            return True, value
        return False, None

    def _is_account_locked(self,
                           latest_lock: datetime,
                           latest_unlock: datetime,
                           locked_hours: int) -> bool:
        """
        Check whether the account has been locked more recently than
        unlocked.

        :param latest_lock: The latest time the account was locked.
        :param latest_unlock: The latest time the account was unlocked.
        :param locked_hours: The number of hours that the account should
            be locked for after a certain number of failed login attempts.
        :return: True if the account is locked, False if the account is
            unlocked.
        """
        # find the time that was locked_hours ago
        locked_time = datetime.utcnow() - timedelta(hours=locked_hours)
        st.write("locked_time", locked_time)
        st.write(type(locked_time))
        # we are locked if the times both exist and the latest lock is
        # more recent, or if the latest lock exists and the latest unlock
        # does not
        if ((latest_lock is not None and latest_unlock is not None
                and latest_lock > latest_unlock and latest_lock > locked_time)
                or
                (latest_lock is not None and latest_unlock is None
                 and latest_lock > locked_time)):
            eh.add_user_error(
                'login',
                "Your account is locked. Please try again later.")
            return True
        return False

    def _check_locked_account(
            self,
            username: str,
            locked_info_function: Union[str, Callable] = None,
            locked_info_args: dict = None,
            locked_hours: int = 24) -> bool:
        """
        Check if we have a locked account for the given username.

        This should include checking whether the account is locked in
        the session_state, which always happens, and checking if there is
        a lock stored elsewhere, such as in a database. The checking of
        the lock elsewhere is not required for this function to run, but
        is HIGHLY RECOMMENDED since the session state can be easily
        cleared by the user, which would allow them to bypass the lock.

        :param username: The username to check.
        :param locked_info_function: The function to pull the locked
            information associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param locked_info_args: Arguments for the locked_info_function.
            See the docstring for login for more information.
        :param locked_hours: The number of hours that the account should
            be locked for after a certain number of failed login attempts.
            The desired number of incorrect attempts is set elsewhere.
        :return: True if the account is LOCKED (or there is an error),
            False if the account is UNLOCKED.
        """
        # first check the session state
        if 'locked_accounts' in st.session_state.stauth and \
                username in st.session_state.stauth['locked_accounts']:
            return True

        # if we have a locked_info_function, check that as well
        if locked_info_function is not None:
            # pull the latest locked and unlocked times
            pull_worked, values = self._pull_locked_unlocked_info(
                username, locked_info_function, locked_info_args)
            st.write("pull_worked", pull_worked)
            st.write("values", values)
            if pull_worked:
                latest_lock, latest_unlock = values
                st.write("latest_lock", latest_lock)
                st.write(type(latest_lock))
                st.write("latest_unlock", latest_unlock)
                st.write(type(latest_unlock))
                if self._is_account_locked(
                        latest_lock, latest_unlock, locked_hours):
                    return True
                else:
                    return False
            else:
                return True
        else:
            return False

    def _password_pull_error_handler(self, indicator: str,
                                     value: str) -> bool:
        """ Records any errors from the password pulling process."""
        if indicator == 'dev_error':
            eh.add_dev_error(
                'login',
                "There was an error checking the user's password. "
                "Error: " + value)
            return False
        elif indicator == 'user_error':
            eh.add_user_error(
                'login',
                "Incorrect username or password.")
            return False
        return True

    def _password_verification_error_handler(
            self, verified: Union[bool, tuple]) -> bool:
        """Check if the password was verified and record an error if
            not."""
        if isinstance(verified, tuple):
            # if we have a tuple, that means we had a 'dev_errors'
            # issue, which should be handled accordingly
            eh.add_dev_error(
                'login',
                "There was an error checking the user's password. "
                "Error: " + verified[1])
            return False
        elif verified:
            return True
        else:
            eh.add_user_error(
                'login',
                "Incorrect username or password.")
            return False

    def _check_pw(
            self,
            password: str,
            username: str,
            password_pull_function: Union[str, Callable],
            password_pull_args: dict = None) -> bool:
        """
        Pulls the expected password and checks the validity of the entered
        password.

        :param password: The entered password.
        :param username: The entered username.
        :param password_pull_function: The function to pull the hashed
            password associated with the username. This can be a callable
            function or a string.

            At a minimum, a callable function should take 'username' as
            an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error'
                or 'success'.
             - The value should be a string that contains the error
                message when the indicator is 'dev_error', None when the
                indicator is 'user_error', and the hashed password when
                the indicator is 'success'. It is None with 'user_error'
                since we will handle that in the calling function and
                create a user_error that tells the user that
                the username or password is incorrect.

            The current pre-defined function types are:
                'bigquery': Pulls the password from a BigQuery table.
        :param password_pull_args: Arguments for the
            password_pull_function. This should not include 'username'
            since that will automatically be added here based on the
            user's input.

            If using 'bigquery' as your password_pull_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            password_col (str): The name of the column in the BigQuery
                table that contains the passwords.
        """
        # add the username to the arguments for the password pull function
        password_pull_args = self._add_username_to_args(
            username, password_pull_args)
        # pull the password
        if isinstance(password_pull_function, str):
            if password_pull_function.lower() == 'bigquery':
                db = BQTools()
                indicator, value = db.pull_password(
                    **password_pull_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The password_pull_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = password_pull_function(**password_pull_args)

        # only continue if we didn't have any issues getting the password
        if self._password_pull_error_handler(indicator, value):
            verified = Hasher([password]).check([value])[0]
            # we can have errors here if the password doesn't match or
            # there is an issue running the check
            return self._password_verification_error_handler(verified)
        return False

    def _store_lock_unlock_time(
            self,
            username: str,
            store_function: Union[str, Callable],
            store_args: dict,
            lock_or_unlock: str) -> Union[None, str]:
        """
        Store the locked or unlocked time associated with the username.

        :param username: The username to store the lock or unlock time
            for.
        :param store_unlocked_time_function: The function to store the
            unlocked datetime associated with the username. This can be a
            callable function or a string.

            The function should pull in store_unlocked_time_args, which
            can be used for things like accessing and storing to a
            database. At a minimum, a callable function should take
            'username' as one of the store_unlocked_time_args, but can
            include other arguments as well. A callable function can
            return an error message as a string, which our error handler
            will handle.

            The current pre-defined function types are:
                'bigquery': Stores the unlocked datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with three columns corresponding to username,
                    locked_time and unlocked_time (see
                    store_unlocked_time_args below for how to define
                    there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_unlocked_time_args: Arguments for the
            store_unlocked_time_function. This should not include
            'username' since that will automatically be added here.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc.

            If using 'bigquery' as your store_unlocked_time_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.
            unlocked_time_col (str): The name of the column in the
                BigQuery table that contains the unlocked_times.
        :param lock_or_unlock: Whether we are storing a lock or unlock
            time. Literally 'lock' or 'unlock'.

        :return: None if there is no error, a string error message if
            there is an error.
        """
        store_args = self._add_username_to_args(username, store_args)
        if isinstance(store_function, str):
            if store_function.lower() == 'bigquery':
                store_args['lock_or_unlock'] = lock_or_unlock
                db = BQTools()
                error = db.store_lock_unlock_times(**store_args)
            else:
                error = ("The store_function method is not recognized. The "
                         "available options are: 'bigquery' or a callable "
                         "function.")
        else:
            error = store_function(**store_args)
        return error

    def _unlock_time_save_error_handler(self, error: str) -> None:
        """
        Records any errors from the unlock time saving process.
        """
        if error is not None:
            st.write("error", error)
            eh.add_dev_error(
                'login',
                "There was an error saving the unlock time. "
                "Error: " + error)
            st.write(st.session_state.stauth['dev_errors']['login']

    def _store_unlock_time_handler(
            self,
            username: str,
            store_unlocked_time_function: Union[str, Callable],
            store_unlocked_time_args: dict) -> None:
        """
        Attempts to store the unlock time, deals with any errors and
        updates the session_state as necessary.

        :param username: The username to store the lock or unlock time
            for.
        :param store_unlocked_time_function: The function to store the
            unlocked times associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param store_unlocked_time_args: Arguments for the
            store_unlocked_times_function. See the docstring for
            login for more information.
        """
        if 'login_unlock' not in st.session_state.stauth:
            st.session_state.stauth['login_unlock'] = []
        # append the current datetime
        st.session_state.stauth['login_unlock'].append(datetime.utcnow())

        if store_unlocked_time_function is not None:
            error = self._store_lock_unlock_time(
                username, store_unlocked_time_function,
                store_unlocked_time_args, 'unlock')
            st.write("error message", error)
            self._unlock_time_save_error_handler(error)

    def _lock_time_save_error_handler(self, error: str) -> None:
        """
        Records any errors from the lock time saving process.
        """
        if error is not None:
            eh.add_dev_error(
                'login',
                "There was an error saving the lock time. "
                "Error: " + error)

    def _store_lock_time_handler(
            self,
            username: str,
            store_locked_time_function: Union[str, Callable],
            store_locked_time_args: dict) -> None:
        """
        Attempts to store the lock time, deals with any errors and
        updates the session_state as necessary.

        :param username: The username to store the lock or unlock time
            for.
        :param store_locked_time_function: The function to store the
            locked times associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param store_locked_time_args: Arguments for the
            store_locked_times_function. See the docstring for
            login for more information.
        """
        error = self._store_lock_unlock_time(
            username, store_locked_time_function, store_locked_time_args,
            'lock')
        self._lock_time_save_error_handler(error)

    def _store_incorrect_attempt(
            self,
            username: str,
            store_incorrect_attempts_function: Union[str, Callable],
            store_incorrect_attempts_args: dict) -> Union[None, str]:
        """
        Store the datetime associated with the username for an incorrect
        login attempt.

        :param username: The username to store the lock or unlock time
            for.
        :param store_incorrect_attempts_function: The function to store
            the datetime and username when an incorrect login attempt
            occurs. This can be a callable function or a string. At a
            minimum, a callable function should take 'username' as an
            argument, but can include other arguments as well. The
            function should pull in store_incorrect_attempts_args, which
            can be used for things like accessing and storing to a
            database. A callable function can return an error message as a
            string, which our error handler will handle.

            The current pre-defined function types are:
                'bigquery': Stores the attempted datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with two columns corresponding to username and
                    datetime (see store_incorrect_attempts_args below for
                    how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. This should not include
            'username' since that will automatically be added here.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc.

            If using 'bigquery' as your store_incorrect_attempts_function,
            the following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.

        :return error: The error message if there is an error, otherwise
            None.
        """
        store_incorrect_attempts_args = self._add_username_to_args(
            username, store_incorrect_attempts_args)
        if isinstance(store_incorrect_attempts_function, str):
            if store_function.lower() == 'bigquery':
                db = BQTools()
                error = db.store_incorrect_login_times(
                    **store_incorrect_attempts_args)
            else:
                error = ("The store_incorrect_attempts_function method is not "
                         "recognized. The available options are: 'bigquery' "
                         "or a callable function.")
        else:
            error = store_incorrect_attempts_function(
                **store_incorrect_attempts_args)
        return error

    def _incorrect_attempts_error_handler(self, error: str) -> None:
        """
        Records any errors from the incorrect attempt saving process.
        """
        if error is not None:
            eh.add_dev_error(
                'login',
                "There was an error saving the incorrect attempt time. "
                "Error: " + error)
            return False
        return True

    def _store_incorrect_attempts_handler(
            self,
            username: str,
            store_incorrect_attempts_function: Union[str, Callable],
            store_incorrect_attempts_args: dict) -> bool:
        """
        Attempts to store the incorrect attempt time and username, deals
        with any errors and updates the session_state as necessary.

        :param username: The username to store the lock or unlock time
            for.
        :param store_incorrect_attempts_function: The function to store
            the incorrect attempts associated with the username. This can
            be a callable function or a string. See the docstring for
            login for more information.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. See the docstring for
            login for more information.

        :return: False if any errors, True if no errors.
        """
        if 'failed_login_attempts' not in st.session_state.stauth:
            st.session_state.stauth['failed_login_attempts'] = []
        # append the current datetime
        st.session_state.stauth['failed_login_attempts'].append(
            datetime.utcnow())

        if store_incorrect_attempts_function is not None:
            error = self._store_incorrect_attempt(
                username, store_incorrect_attempts_function,
                store_incorrect_attempts_args)
            return self._incorrect_attempts_error_handler(error)
        else:
            return True

    def _incorrect_attempts_pull_error_handler(self, indicator: str,
                                               value: str) -> bool:
        """ Records any errors from the incorrect attempts pulling
            process."""
        if indicator == 'dev_error':
            eh.add_dev_error(
                'login',
                "There was an error pulling incorrect login attempts. "
                "Error: " + value)
            return False
        return True

    def _pull_incorrect_attempts(
            self,
            username: str,
            pull_incorrect_attempts_function: Union[str, Callable] = None,
            pull_incorrect_attempts_args: dict = None) -> (
            Tuple[bool, Union[pd.Series, None]]):
        """
        Pull incorrect login attempts for a given username.

        :param username: The username to check.
        :param pull_incorrect_attempts_function: The function to pull the
            datetimes associated with a username for incorrect login
            attempts. This can be a callable function or a string.

            The function should pull in pull_incorrect_attempts_args,
            which can be used for things like accessing and pulling from a
            database. At a minimum, a callable function should take
            'username' as one of the pull_incorrect_attempts_args, but can
            include other arguments as well.
            A callable function should return:
            - A tuple of an indicator and a value
            - The indicator should be either 'dev_error' or 'success'.
            - The value should be a string that contains the error
                message when the indicator is 'dev_error' and a
                pandas series of datetimes (if data exists) or None (if
                data does not exist) when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the incorrect login datetimes from a
                    BigQuery table.
                    This pre-defined version will look for a table
                    with two columns corresponding to username and
                    datetime (see pull_incorrect_attempts_args below for
                    how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. This should not include
            'username' since that will automatically be added here.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc.

            If using 'bigquery' as your pull_incorrect_attempts_function,
            the following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.

        :return: Tuple with the first value of True if the pull worked and
            False if there were errors with the pull. The second value
            should be either a pandas Series if the pull worked and there
            is existing data or None if the pull "worked" but no data yet
            exists in the database. The second value will be None if there
            was an error.
        """
        # add the username to the arguments
        pull_incorrect_attempts_args = self._add_username_to_args(
            username, pull_incorrect_attempts_args)
        if isinstance(pull_incorrect_attempts_function, str):
            if pull_incorrect_attempts_function.lower() == 'bigquery':
                db = BQTools()
                indicator, value = db.pull_incorrect_attempts(
                    **pull_incorrect_attempts_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The pull_incorrect_attempts_function method is not "
                    "recognized. The available options are: 'bigquery' or a "
                    "callable function.")
        else:
            indicator, value = pull_incorrect_attempts_function(
                **pull_incorrect_attempts_args)

        if self._incorrect_attempts_pull_error_handler(indicator, value):
            return True, value
        return False, None

    def _check_too_many_attempts(
            self,
            username: str,
            pull_incorrect_attempts_function: Union[str, Callable] = None,
            pull_incorrect_attempts_args: dict = None,
            locked_info_function: Union[str, Callable] = None,
            locked_info_args: dict = None,
            locked_hours: int = 24,
            incorrect_attempts: int = 10) -> bool:
        """
        Check if we have too many login attempts for the given username.

        :param username: The username to check.
        :param pull_incorrect_attempts_function: The function to pull the
            incorrect attempts associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. See the docstring for
            login for more information.
        :param locked_info_function: The function to pull the locked
            information associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param locked_info_args: Arguments for the locked_info_function.
            See the docstring for login for more information.
        :param locked_hours: The number of hours that the account should
            be locked for after a certain number of failed login attempts.
        :param incorrect_attempts: The number of incorrect attempts
            allowed before the account is locked.

        :return: True if account should be locked, False if account should
            be unlocked.
        """
        # first try pulling the data from a database if we have one we
        # are using for this purpose
        if pull_incorrect_attempts_function is not None:
            attempts_pull_worked, attempts = self._pull_incorrect_attempts(
                username, pull_incorrect_attempts_function,
                pull_incorrect_attempts_args)
            st.write("attempts_pull_worked", attempts_pull_worked)
            st.write("attempts", attempts)
            locks_pull_worked, lock_unlock = self._pull_locked_unlocked_info(
                username, locked_info_function, locked_info_args)
            _, latest_unlock = lock_unlock
            st.write("locks_pull_worked", locks_pull_worked)
            st.write("latest_unlock", latest_unlock)
        else:
            # if not, just use the session_state
            if 'failed_login_attempts' in st.session_state.stauth:
                attempts = pd.Series(st.session_state.stauth[
                                         'failed_login_attempts'])
            else:
                attempts = None
            if 'login_unlock' in st.session_state.stauth:
                latest_unlock = st.session_state.stauth['login_unlock'][-1]
            else:
                latest_unlock = None
            attempts_pull_worked = True
            locks_pull_worked = True

        if attempts_pull_worked and locks_pull_worked and attempts is not None:
            # sort attempts by datetime, starting with the most recent
            attempts = attempts.sort_values('datetime', ascending=False)
            st.write("attempts", attempts)
            # count the number of attempts in the last locked_hours
            recent_attempts = attempts[
                attempts['datetime'] > datetime.utcnow() - timedelta(
                    hours=locked_hours)]
            st.write("recent_attempts", recent_attempts)
            # count the number of attempts after latest_unlock
            if latest_unlock is not None:
                recent_attempts = recent_attempts[
                    recent_attempts['datetime'] > latest_unlock]
                st.write("recent_attempts", recent_attempts)
            if len(recent_attempts) >= incorrect_attempts:
                eh.add_user_error(
                    'login',
                    "Your account is locked. Please try again later.")
                return True
            else:
                return False
        elif attempts is None:
            return False
        else:
            # if the data pulls didn't work, we want to lock the account
            # to be safe
            eh.add_user_error(
                'login',
                "Your account is locked. Please try again later.")
            return True

    def _check_credentials(
            self,
            username_text_key: str,
            password_text_key: str,
            password_pull_function: Union[str, Callable],
            password_pull_args: dict = None,
            incorrect_attempts: int = 10,
            locked_hours: int = 24,
            locked_info_function: Union[str, Callable] = None,
            locked_info_args: dict = None,
            store_locked_time_function: Union[str, Callable] = None,
            store_locked_time_args: dict = None,
            store_unlocked_time_function: Union[str, Callable] = None,
            store_unlocked_time_args: dict = None,
            store_incorrect_attempts_function: Union[str, Callable] = None,
            store_incorrect_attempts_args: dict = None,
            pull_incorrect_attempts_function: Union[str, Callable] = None,
            pull_incorrect_attempts_args: dict = None) -> None:
        """
        Checks the validity of the entered credentials, including making
        sure the number of incorrect attempts is not exceeded.

        Note that we have one potential error that can persist even after
        a good login. This is any dev_error that occurs when storing the
        unlock time. If we don't store the unlock time, the user can still
        proceed, but as a developer, you might want to still display or
        record that error.

        :param username_text_key: The st.session_state name used to access
            the username.
        :param password_text_key: The st.session_state name used to access
            the password.
        :param password_pull_function: The function to pull the password
            associated with the username. This can be a callable function
            or a string. See the docstring for login for more information.
        :param password_pull_args: Arguments for the
            password_pull_function. See the docstring for login for more
            information.
        :param incorrect_attempts: The number of incorrect attempts
            allowed before the account is locked.
        :param locked_hours: The number of hours the account is locked
            after exceeding the number of incorrect attempts.

        The following parameters are all associated with the pattern of
        storing incorrect login attempts to a database, as well as storing
        the times of a username being locked and unlocked. If the user
        successfully logs in, an unlocked time is added to the database,
        so that we know the account is currently unlocked. If too many
        incorrect attempts occur at logging in, the account is locked for
        locked_hours.
        This database pattern isn't required, but is HIGHLY RECOMMENDED.
        If not used, the session_state will still record incorrect login
        attempts and if an account is locked or not, but that can easily
        be disregarded by refreshing the website.

        :param locked_info_function: The function to pull the locked
            information associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param locked_info_args: Arguments for the locked_info_function.
            See the docstring for login for more information.
        :param store_locked_time_function: The function to store the
            locked times associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param store_locked_time_args: Arguments for the
            store_locked_times_function. See the docstring for
            login for more information.
        :param store_unlocked_time_function: The function to store the
            unlocked times associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param store_unlocked_time_args: Arguments for the
            store_unlocked_times_function. See the docstring for
            login for more information.
        :param store_incorrect_attempts_function: The function to store
            the incorrect attempts associated with the username. This can
            be a callable function or a string. See the docstring for
            login for more information.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. See the docstring for
            login for more information.
        :param pull_incorrect_attempts_function: The function to pull the
            incorrect attempts associated with the username. This can be a
            callable function or a string. See the docstring for
            login for more information.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. See the docstring for
            login for more information.
        """
        username = st.session_state[username_text_key]
        password = st.session_state[password_text_key]

        # make sure the username and password aren't blank
        # and only continue if the username exists in our list
        if self._check_login_info(username, password) and \
                self._check_username(username):

            ##############################################################
            # _check_locked_account works when there is nothing to pull
            # _check_pw works if correct password is entered
            ##############################################################

            # first see if the account has been locked
            if self._check_locked_account(username, locked_info_function,
                                          locked_info_args, locked_hours):
                if 'locked_accounts' not in st.session_state.stauth:
                    st.session_state.stauth['locked_accounts'] = []
                st.session_state.stauth['locked_accounts'].append(username)
                st.session_state.stauth['authentication_status'] = False
            else:
                # only continue if the password is correct
                if self._check_pw(password, username, password_pull_function,
                                  password_pull_args):
                    st.write("password correct")
                    # note that even with errors storing the data, we
                    # still let the user login, so we clear the errors
                    # first, so that we can record any storage errors and
                    # have them accessible later on
                    eh.clear_errors()
                    # if we have a store_unlocked_time_function, store the
                    # unlocked time
                    self._store_unlock_time_handler(
                        username, store_unlocked_time_function,
                        store_unlocked_time_args)
                    st.session_state.stauth['username'] = username
                    st.session_state.stauth['authentication_status'] = True
                else:
                    st.write("password wrong")
                    st.session_state.stauth['authentication_status'] = False
                    if (not self._store_incorrect_attempts_handler(
                            username, store_incorrect_attempts_function,
                            store_incorrect_attempts_args)
                            or
                            self._check_too_many_attempts(
                                username, pull_incorrect_attempts_function,
                                pull_incorrect_attempts_args,
                                locked_info_function, locked_info_args,
                                locked_hours, incorrect_attempts)):
                        st.write("too many attempts")
                        if 'locked_accounts' not in st.session_state.stauth:
                            st.session_state.stauth['locked_accounts'] = []
                        st.session_state.stauth['locked_accounts'].append(
                            username)
                        self._store_lock_time_handler(
                            username, store_locked_time_function,
                            store_locked_time_args)
                    else:
                        eh.add_user_error(
                            'login',
                            "Incorrect username or password.")
        else:
            # here we have already set any errors in previous functions,
            # so just set authentication_status to false
            st.session_state.stauth['authentication_status'] = False

    def login(self,
              location: str = 'main',
              username_text_key: str = 'login_username',
              password_text_key: str = 'login_password',
              password_pull_function: Union[str, Callable] = 'bigquery',
              password_pull_args: dict = None,
              incorrect_attempts: int = 10,
              locked_hours: int = 24,
              locked_info_function: Union[str, Callable] = None,
              locked_info_args: dict = None,
              store_locked_time_function: Union[str, Callable] = None,
              store_locked_time_args: dict = None,
              store_unlocked_time_function: Union[str, Callable] = None,
              store_unlocked_time_args: dict = None,
              store_incorrect_attempts_function: Union[str, Callable] = None,
              store_incorrect_attempts_args: dict = None,
              pull_incorrect_attempts_function: Union[str, Callable] = None,
              pull_incorrect_attempts_args: dict = None) -> None:
        """
        Creates a login widget.

        Note that this method does not check for whether a user is already
        logged in, that should happen separately from this method, with
        this method one of the resulting options. For example:
        if check_authentication_status():
            main()
        else:
            stauth.login()
            # you might also want a register_user widget here

        Note that we have one potential error that can persist even after
        a good login. This is any dev_errors that occurs when storing the
        unlock time. If we don't store the unlock time, the user can still
        proceed, but as a developer, you might want to still display or
        record that error.

        :param location: The location of the login form i.e. main or
            sidebar.
        :param username_text_key: The key for the username text input on
            the login form. We attempt to default to a unique key, but you
            can put your own in here if you want to customize it or have
            clashes with other keys/forms.
        :param password_text_key: The key for the password text input on
            the login form. We attempt to default to a unique key, but you
            can put your own in here if you want to customize it or have
            clashes with other keys/forms.
        :param password_pull_function: The function to pull the password
            associated with the username. This can be a callable function
            or a string.

            At a minimum, a callable function should take 'username' as
            an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error'
                or 'success'.
             - The value should be a string that contains the error
                message when the indicator is 'dev_error', None when the
                indicator is 'user_error', and the hashed password when
                the indicator is 'success'. It is None with 'user_error'
                since we will handle that in the calling function and
                create a user_errors that tells the user that the
                username or password was incorrect.

            The current pre-defined function types are:
                'bigquery': Pulls the password from a BigQuery table. It
                    performs a basic SQL lookup to see if there are any
                    passwords associated with the given username and, if
                    so, returns that (hashed) password.
        :param password_pull_args: Arguments for the
            password_pull_function.

            If using 'bigquery' as your password_pull_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            password_col (str): The name of the column in the BigQuery
                table that contains the passwords.
        :param incorrect_attempts: The number of incorrect attempts
            allowed before the account is locked.
        :param locked_hours: The number of hours the account is locked
            after exceeding the number of incorrect attempts.

        The following parameters are all associated with the pattern of
        storing incorrect login attempts to a database, as well as storing
        the times of a username being locked and unlocked. If the user
        successfully logs in, an unlocked time is added to the database,
        so that we know the account is currently unlocked. If too many
        incorrect attempts occur at logging in, the account is locked for
        locked_hours.
        This database pattern isn't required, but is HIGHLY RECOMMENDED.
        If not used, the session_state will still record incorrect login
        attempts and if an account is locked or not, but that can easily
        be disregarded by refreshing the website.

        :param locked_info_function: The function to pull the locked
            information associated with the username. This can be a
            callable function or a string.

            The function should pull in locked_info_args, which can be
            used for things like accessing and pulling from a database.
            At a minimum, a callable function should take 'username' as
            one of the locked_info_args, but can include other arguments
            as well.
            A callable function should return:
            - A tuple of an indicator and a value
            - The indicator should be either 'dev_error' or 'success'.
            - The value should be a string that contains the error
                message when the indicator is 'dev_error' and a
                tuple of (latest_lock_datetime, latest_unlock_datetime)
                when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the locked and unlocked datetimes from a
                    BigQuery table.
                    This pre-defined version will look for a table with
                    three columns corresponding to username, locked_time
                    and unlocked_time (see locked_info_args below for how
                    to define there). If the account is locked, the latest
                    locked_time will be more recent than the latest
                    unlocked_time. Note that if using 'bigquery' here,
                    in our other database functions, you should
                    also be using the 'bigquery' option or using your own
                    method that writes to a table set up in the same way.
        :param locked_info_args: Arguments for the locked_info_function.
            This should not include 'username' since that will
            automatically be added here. Instead, it should include things
            like database name, table name, credentials to log into the
            database, etc.

            If using 'bigquery' as your locked_info_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.
            unlocked_time_col (str): The name of the column in the
                BigQuery table that contains the unlocked_times.
        :param store_locked_time_function: The function to store the
            locked datetime associated with the username. This can be a
            callable function or a string.

            The function should pull in store_locked_time_args, which can
            be used for things like accessing and storing to a database.
            At a minimum, a callable function should take 'username' as
            one of the locked_info_args, but can include other arguments
            as well. A callable function can return an error message
            as a string, which our error handler will handle.

            The current pre-defined function types are:
                'bigquery': Stores the locked datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with three columns corresponding to username,
                    locked_time and unlocked_time (see
                    store_locked_time_args below for how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_locked_time_args: Arguments for the
            store_locked_time_function. This should not include 'username'
            since that will automatically be added here. Instead, it
            should include things like database name, table name,
            credentials to log into the database, etc.

            If using 'bigquery' as your store_locked_time_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.
            unlocked_time_col (str): The name of the column in the
                BigQuery table that contains the unlocked_times.
        :param store_unlocked_time_function: The function to store the
            unlocked times associated with the username. See
            store_locked_time_function above - this just stores the unlock
            time instead of the lock time.
        :param store_unlocked_time_args: Arguments for the
            store_unlocked_times_function. See
            store_locked_time_args above - these variable will be the same
            here.
        :param store_incorrect_attempts_function: The function to store
            the datetime and username when an incorrect login attempt
            occurs. This can be a callable function or a string. At a
            minimum, a callable function should take 'username' as an
            argument, but can include other arguments as well. The
            function should pull in store_incorrect_attempts_args, which
            can be used for things like accessing and storing to a
            database. A callable function can return an error message as a
            string, which our error handler will handle.

            The current pre-defined function types are:
                'bigquery': Stores the attempted datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with two columns corresponding to username and
                    datetime (see store_incorrect_attempts_args below for
                    how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. This should not include
            'username' since that will automatically be added here.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc.

            If using 'bigquery' as your store_incorrect_attempts_function,
            the following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.
        :param pull_incorrect_attempts_function: The function to pull the
            datetimes associated with a username for incorrect login
            attempts. This can be a callable function or a string.

            The function should pull in pull_incorrect_attempts_args,
            which can be used for things like accessing and pulling from a
            database. At a minimum, a callable function should take
            'username' as one of the pull_incorrect_attempts_args, but can
            include other arguments as well.
            A callable function should return:
            - A tuple of an indicator and a value
            - The indicator should be either 'dev_error' or 'success'.
            - The value should be a string that contains the error
                message when the indicator is 'dev_error' and a
                pandas series of datetimes (if data exists) or None (if
                data does not exist) when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the incorrect login datetimes from a
                    BigQuery table.
                    This pre-defined version will look for a table
                    with two columns corresponding to username and
                    datetime (see pull_incorrect_attempts_args below for
                    how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. This should not include
            'username' since that will automatically be added here.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc.

            If using 'bigquery' as your pull_incorrect_attempts_function,
            the following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.
        """
        # check whether the inputs are within the correct set of options
        if not self._check_login_session_states() or \
                not self._check_login_inputs(location) or \
                not self._check_storage_functions(
                    locked_info_function, store_locked_time_function,
                    store_unlocked_time_function,
                    store_incorrect_attempts_function,
                    pull_incorrect_attempts_function):
            return False

        if location == 'main':
            login_form = st.form('Login')
        elif location == 'sidebar':
            login_form = st.sidebar.form('Login')

        login_form.subheader('Login')
        # we need keys for all of these so they can be accessed in the
        # callback through session_state (such as
        # st.session_state['login_user_username_email'])
        username = login_form.text_input(
            'Username', key=username_text_key).lower()
        password = login_form.text_input(
            'Password', type='password', key=password_text_key)

        login_form.form_submit_button(
            'Login', on_click=self._check_credentials,
            args=(username_text_key, password_text_key,
                  password_pull_function, password_pull_args,
                  incorrect_attempts, locked_hours,
                  locked_info_function, locked_info_args,
                  store_locked_time_function, store_locked_time_args,
                  store_unlocked_time_function, store_unlocked_time_args,
                  store_incorrect_attempts_function,
                  store_incorrect_attempts_args,
                  pull_incorrect_attempts_function,
                  pull_incorrect_attempts_args))

    def logout(self, button_name: str, location: str='main', key: str=None):
        """
        Creates a logout button.

        Parameters
        ----------
        button_name: str
            The rendered name of the logout button.
        location: str
            The location of the logout button i.e. main or sidebar.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            if st.button(button_name, key):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None
        elif location == 'sidebar':
            if st.sidebar.button(button_name, key):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None

    def _update_password(self, username: str, password: str):
        """
        Updates credentials dictionary with user's reset hashed password.

        Parameters
        ----------
        username: str
            The username of the user to update the password for.
        password: str
            The updated plain text password.
        """
        self.credentials['usernames'][username]['password'] = Hasher([password]).generate()[0]

    def reset_password(self, username: str, form_name: str, location: str='main') -> bool:
        """
        Creates a password reset widget.

        Parameters
        ----------
        username: str
            The username of the user to reset the password for.
        form_name: str
            The rendered name of the password reset form.
        location: str
            The location of the password reset form i.e. main or sidebar.
        Returns
        -------
        str
            The status of resetting the password.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            reset_password_form = st.form('Reset password')
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form('Reset password')
        
        reset_password_form.subheader(form_name)
        self.username = username.lower()
        self.password = reset_password_form.text_input('Current password', type='password')
        new_password = reset_password_form.text_input('New password', type='password')
        new_password_repeat = reset_password_form.text_input('Repeat password', type='password')

        if reset_password_form.form_submit_button('Reset'):
            if self._check_credentials(inplace=False):
                if len(new_password) > 0:
                    if new_password == new_password_repeat:
                        if self.password != new_password: 
                            self._update_password(self.username, new_password)
                            return True
                        else:
                            raise ResetError('New and current passwords are the same')
                    else:
                        raise ResetError('Passwords do not match')
                else:
                    raise ResetError('No new password provided')
            else:
                raise CredentialsError('password')

    def _set_random_password(self, username: str) -> str:
        """
        Updates credentials dictionary with user's hashed random password.

        Parameters
        ----------
        username: str
            Username of user to set random password for.
        Returns
        -------
        str
            New plain text password that should be transferred to user securely.
        """
        self.random_password = generate_random_pw()
        self.credentials['usernames'][username]['password'] = Hasher([self.random_password]).generate()[0]
        return self.random_password

    def forgot_password(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a forgot password widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot password form.
        location: str
            The location of the forgot password form i.e. main or sidebar.
        Returns
        -------
        str
            Username associated with forgotten password.
        str
            Email associated with forgotten password.
        str
            New plain text password that should be transferred to user securely.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_password_form = st.form('Forgot password')
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form('Forgot password')

        forgot_password_form.subheader(form_name)
        username = forgot_password_form.text_input('Username').lower()

        if forgot_password_form.form_submit_button('Submit'):
            if len(username) > 0:
                if username in self.credentials['usernames']:
                    return username, self.credentials['usernames'][username]['email'], self._set_random_password(username)
                else:
                    return False, None, None
            else:
                raise ForgotError('Username not provided')
        return None, None, None

    def _get_username(self, key: str, value: str) -> str:
        """
        Retrieves username based on a provided entry.

        Parameters
        ----------
        key: str
            Name of the credential to query i.e. "email".
        value: str
            Value of the queried credential i.e. "jsmith@gmail.com".
        Returns
        -------
        str
            Username associated with given key, value pair i.e. "jsmith".
        """
        for username, entries in self.credentials['usernames'].items():
            if entries[key] == value:
                return username
        return False

    def forgot_username(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a forgot username widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot username form.
        location: str
            The location of the forgot username form i.e. main or sidebar.
        Returns
        -------
        str
            Forgotten username that should be transferred to user securely.
        str
            Email associated with forgotten username.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_username_form = st.form('Forgot username')
        elif location == 'sidebar':
            forgot_username_form = st.sidebar.form('Forgot username')

        forgot_username_form.subheader(form_name)
        email = forgot_username_form.text_input('Email')

        if forgot_username_form.form_submit_button('Submit'):
            if len(email) > 0:
                return self._get_username('email', email), email
            else:
                raise ForgotError('Email not provided')
        return None, email

    def _update_entry(self, username: str, key: str, value: str):
        """
        Updates credentials dictionary with user's updated entry.

        Parameters
        ----------
        username: str
            The username of the user to update the entry for.
        key: str
            The updated entry key i.e. "email".
        value: str
            The updated entry value i.e. "jsmith@gmail.com".
        """
        self.credentials['usernames'][username][key] = value

    def update_user_details(self, username: str, form_name: str, location: str='main') -> bool:
        """
        Creates a update user details widget.

        Parameters
        ----------
        username: str
            The username of the user to update user details for.
        form_name: str
            The rendered name of the update user details form.
        location: str
            The location of the update user details form i.e. main or sidebar.
        Returns
        -------
        str
            The status of updating user details.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            update_user_details_form = st.form('Update user details')
        elif location == 'sidebar':
            update_user_details_form = st.sidebar.form('Update user details')
        
        update_user_details_form.subheader(form_name)
        self.username = username.lower()
        field = update_user_details_form.selectbox('Field', ['Name', 'Email']).lower()
        new_value = update_user_details_form.text_input('New value')

        if update_user_details_form.form_submit_button('Update'):
            if len(new_value) > 0:
                if new_value != self.credentials['usernames'][self.username][field]:
                    self._update_entry(self.username, field, new_value)
                    if field == 'name':
                            st.session_state['name'] = new_value
                            self.exp_date = self._set_exp_date()
                            self.token = self._token_encode()
                            self.cookie_manager.set(self.cookie_name, self.token,
                            expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                    return True
                else:
                    raise UpdateError('New and current values are the same')
            if len(new_value) == 0:
                raise UpdateError('New value not provided')

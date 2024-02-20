import bcrypt
import extra_streamlit_components as stx
import jwt
import streamlit as st

from datetime import datetime, timedelta
from typing import Union

from .Hasher import Hasher
from .Validator import Validator
from .utils import generate_random_pw
from .exceptions import CredentialsError, ForgotError, RegisterError, ResetError, UpdateError

from StreamlitAuth import ErrorHandling as eh
from StreamlitAuth.Email import Email
from StreamlitAuth.Encryptor import GenericEncryptor, GoogleEncryptor


class Authenticate(object):
    """
    Create register user, login, forgot password, forgot username,
    reset password, reset username and logout methods/widgets.

    :method register_user: Creates a new user registration widget.
    """
    def __init__(self, usernames_session_state: str,
                 emails_session_state: str,
                 user_credentials_session_state: str,
                 preauthorized_session_state: str = None,
                 weak_passwords: list = [],
                 cookie_name: str=None, cookie_key: str=None,
                 cookie_expiry_days: float=30.0,) -> None:
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
        :param cookie_name: The name of the JWT cookie stored on the
            client's browser for passwordless reauthentication.
        :param cookie_key: The key to be used for hashing the signature of
            the JWT cookie.
        :param cookie_expiry_days: The number of days before the cookie
            expires on the client's browser.
        """
        self.usernames_session_state = usernames_session_state
        self.emails_session_state = emails_session_state
        self.user_credentials_session_state = user_credentials_session_state
        self.preauthorized_session_state = preauthorized_session_state
        self.weak_passwords = weak_passwords
        self.cookie_name = cookie_name
        self.cookie_key = cookie_key
        self.cookie_expiry_days = cookie_expiry_days

        self.cookie_manager = stx.CookieManager()

        if 'stauth' not in st.session_state:
            st.session_state['stauth'] = {}
        if 'authentication_status' not in st.session_state.stauth:
            st.session_state.stauth['authentication_status'] = None
        if 'username' not in st.session_state.stauth:
            st.session_state.stauth['username'] = None
        if 'logout' not in st.session_state.stauth:
            st.session_state.stauth['logout'] = None

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

    def _check_register_user_inputs(self, location: str,
                                    encrypt_type: str) -> bool:
        """
        Check whether the register_user inputs are within the correct set
        of options.
        """
        if location not in ['main', 'sidebar']:
            eh.add_dev_error(
                'register_user',
                "location argument must be one of 'main' or 'sidebar'")
            return False
        if encrypt_type.lower() not in ['generic', 'google']:
            eh.add_dev_error(
                'register_user',
                "encrypt_type argument must be one of 'generic' or 'google'")
            return False
        return True

    def _check_user_info(
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
                              email: str, preauthorization: bool,
                              encrypt_type: str, **kwargs) -> None:
        """
        Adds to credentials dictionary the new user's information.

        Note that for the generic version we get and store a key and
        token for each username and email, while for the google version
        we just get and store a ciphertext for each username and email
        (the key is typically the same and is what is accessed by
        passing in 'kms_credentials' through kwargs).

        :param username: The username of the new user.
        :param password: The password of the new user.
        :param email: The email of the new user.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param encrypt_type: The type of encryption to use for the user
            credentials.
            'generic': Fernet symmetric encryption.
            'google': Google Cloud KMS (Key Management Service) API.
        :param **kwargs: Additional arguments for the encryption.
            Currently only needed if using 'google' encryption, in which
            case the following arguments are required:
            project_id (string): Google Cloud project ID
            (e.g. 'my-project').
            location_id (string): Cloud KMS location (e.g. 'us-east1').
            key_ring_id (string): ID of the Cloud KMS key ring
            (e.g. 'my-key-ring').
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
        # we want to add our new username and email to the session state,
        # so they can't be accidentally registered again
        st.session_state[self.usernames_session_state].append(username)
        st.session_state[self.emails_session_state].append(email)

        # encrypt / hash info
        if encrypt_type.lower() == 'generic':
            encryptor = GenericEncryptor()
        elif encrypt_type.lower() == 'google':
            encryptor = GoogleEncryptor(**kwargs)
        enc_username = encryptor.encrypt(username)
        enc_email = encryptor.encrypt(email)
        password = Hasher([password]).generate()[0]

        # store the credentials
        # note that for the generic version we get and store a key and
        # token for each username and email, while for the google version
        # we just get and store a ciphertext for each username and email
        # (the key is typically the same and is what is accessed by
        # passing in 'kms_credentials' through kwargs)
        if encrypt_type.lower() == 'generic':
            st.session_state[self.user_credentials_session_state] = {
                'username': {'key': enc_username[0],
                             'token': enc_username[1]},
                'email': {'key': enc_email[0],
                          'token': enc_email[1]},
                'password': password}
        elif encrypt_type.lower() == 'google':
            st.session_state[self.user_credentials_session_state] = {
                'username': enc_username.ciphertext,
                'email': enc_email.ciphertext,
                'password': password}

        # if we had the name preauthorized, remove it from that list
        if preauthorization:
            st.session_state[self.preauthorized_session_state].remove(email)

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

    def _check_and_register_user(
            self, email_text_key: str, username_text_key: str,
            password_text_key: str, repeat_password_text_key: str,
            preauthorization: bool, encrypt_type: str,
            email_user: str = None, website_name: str = None,
            website_email: str = None, **kwargs) -> None:
        """
        Once a new user submits their info, this is a callback to check
        the validity of their input and register them if valid.

        :param new_email: The session state name to access the new user's
            email.
        :param new_username: The session state name to access the new
            user's username.
        :param new_password: The session state name to access the new
            user's password.
        :param new_password_repeat: The session state name to access the
            new user's repeated password.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param encrypt_type: The type of encryption to use for the user
            credentials.
            'generic': Fernet symmetric encryption.
            'google': Google Cloud KMS (Key Management Service) API.
        :param email_user: If we want to email the user after registering,
            provide the method for email here.
            "app_engine" - the web app is hosted on Google App Engine.
            https://cloud.google.com/appengine/docs/standard/python3/services/mail
            "gmail" - the user wants to use their Gmail account to send
            the email and must have the gmail API enabled.
            https://developers.google.com/gmail/api/guides
        :param website_name: The name of the website where the
            registration is happening. This will be included in the email
            and so is only necessary if email_user is True.
        :param website_email: The email that is sending the registration
            confirmation. This will be included in the email
            and so is only necessary if email_user is True.
        :param **kwargs: Additional arguments for the encryption.
            Currently only needed if using 'google' encryption. See
            the docstring for register_user for more information.
        """
        new_email = st.session_state[email_text_key]
        new_username = st.session_state[username_text_key]
        new_password = st.session_state[password_text_key]
        new_password_repeat = st.session_state[repeat_password_text_key]
        if self._check_user_info(
                new_email, new_username, new_password, new_password_repeat,
                preauthorization):
            self._register_credentials(
                new_username, new_password, new_email, preauthorization,
                encrypt_type, **kwargs)
            # get rid of any errors, since we have successfully registered
            eh.clear_errors()
            if email_user is not None:
                email_handler = Email(new_email, new_username, website_name,
                                      website_email)
                if self._check_email_inputs(website_name, website_email):
                    if email_user.lower() == 'app_engine':
                        email_handler.app_engine_email_registered_user()
                    elif email_user.lower() == 'gmail':
                        email_handler.gmail_email_registered_user()

    def register_user(self, location: str = 'main',
                      preauthorization: bool = True,
                      encrypt_type: str = 'google',
                      email_text_key: str = 'register_user_email',
                      username_text_key: str = 'register_user_username',
                      password_text_key: str = 'register_user_password',
                      repeat_password_text_key: str =
                      'register_user_repeat_password',
                      email_user: str = None,
                      website_name: str = None,
                      website_email: str = None,
                      **kwargs) -> None:
        """
        Creates a new user registration widget.

        Note that for the generic version we get and store a key and
        token for each username and email, while for the google version
        we just get and store a ciphertext for each username and email
        (the key is typically the same for all encrypted texts and is what
        is accessed by passing in 'kms_credentials' through kwargs).

        :param location: The location of the register new user form i.e.
            main or sidebar.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param encrypt_type: The type of encryption to use for the user
            credentials.
            'generic': Fernet symmetric encryption.
            'google': Google Cloud KMS (Key Management Service) API.
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
            provide the method for email here.
            "app_engine" - the web app is hosted on Google App Engine.
            https://cloud.google.com/appengine/docs/standard/python3/services/mail
            "gmail" - the user wants to use their Gmail account to send
            the email and must have the gmail API enabled.
            https://developers.google.com/gmail/api/guides
        :param website_name: The name of the website where the
            registration is happening. This will be included in the email
            and so is only necessary if email_user is True.
        :param website_email: The email that is sending the registration
            confirmation. This will be included in the email
            and so is only necessary if email_user is True.
        :param **kwargs: Additional arguments for the encryption.
            Currently only needed if using 'google' encryption, in which
            case the following arguments are required:
            project_id (string): Google Cloud project ID
            (e.g. 'my-project').
            location_id (string): Cloud KMS location (e.g. 'us-east1').
            key_ring_id (string): ID of the Cloud KMS key ring
            (e.g. 'my-key-ring').
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
        # check on whether all session state inputs exist and are the
        # correct type and whether the inputs are within the correct set
        # of options
        if not self._check_register_user_session_states(preauthorization) or \
                not self._check_register_user_inputs(location, encrypt_type):
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
                  repeat_password_text_key, preauthorization, encrypt_type,
                  email_user, website_name, website_email),
            kwargs=kwargs)

    def _token_encode(self) -> str:
        """
        Encodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        return jwt.encode({'name':st.session_state['name'],
            'username':st.session_state['username'],
            'exp_date':self.exp_date}, self.cookie_key, algorithm='HS256')

    def _token_decode(self) -> str:
        """
        Decodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        try:
            return jwt.decode(self.token, self.cookie_key, algorithms=['HS256'])
        except:
            return False

    def _set_exp_date(self) -> str:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def _check_pw(self) -> bool:
        """
        Checks the validity of the entered password.

        Returns
        -------
        bool
            The validity of the entered password by comparing it to the hashed password on disk.
        """
        return bcrypt.checkpw(self.password.encode(), 
            self.credentials['usernames'][self.username]['password'].encode())

    def _check_cookie(self):
        """
        Checks the validity of the reauthentication cookie.
        """
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if self.token is not False:
                if not st.session_state['logout']:
                    if self.token['exp_date'] > datetime.utcnow().timestamp():
                        if 'name' and 'username' in self.token:
                            st.session_state['name'] = self.token['name']
                            st.session_state['username'] = self.token['username']
                            st.session_state['authentication_status'] = True
    
    def _check_credentials(self, inplace: bool=True) -> bool:
        """
        Checks the validity of the entered credentials.

        Parameters
        ----------
        inplace: bool
            Inplace setting, True: authentication status will be stored in session state, 
            False: authentication status will be returned as bool.
        Returns
        -------
        bool
            Validity of entered credentials.
        """
        if self.username in self.credentials['usernames']:
            try:
                if self._check_pw():
                    if inplace:
                        st.session_state['name'] = self.credentials['usernames'][self.username]['name']
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(self.cookie_name, self.token,
                            expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                        st.session_state['authentication_status'] = True
                    else:
                        return True
                else:
                    if inplace:
                        st.session_state['authentication_status'] = False
                    else:
                        return False
            except Exception as e:
                print(e)
        else:
            if inplace:
                st.session_state['authentication_status'] = False
            else:
                return False

    def login(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a login widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
        Returns
        -------
        str
            Name of the authenticated user.
        bool
            The status of authentication, None: no credentials entered, 
            False: incorrect credentials, True: correct credentials.
        str
            Username of the authenticated user.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not st.session_state['authentication_status']:
            self._check_cookie()
            if not st.session_state['authentication_status']:
                if location == 'main':
                    login_form = st.form('Login')
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login')

                login_form.subheader(form_name)
                self.username = login_form.text_input('Username').lower()
                st.session_state['username'] = self.username
                self.password = login_form.text_input('Password', type='password')

                if login_form.form_submit_button('Login'):
                    self._check_credentials()

        return st.session_state['name'], st.session_state['authentication_status'], st.session_state['username']

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

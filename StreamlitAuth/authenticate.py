import bcrypt
import extra_streamlit_components as stx
import jwt
import streamlit as st

from datetime import datetime, timedelta
from typing import Union

from .hasher import Hasher
from .validator import Validator
from .utils import generate_random_pw
from .exceptions import CredentialsError, ForgotError, RegisterError, ResetError, UpdateError

from StreamlitAuth import ErrorHandling as eh
from StreamlitAuth.Encryptor import GenericEncryptor, GoogleEncryptor


class Authenticate(object):
    """
    This class will create login, logout, register user, reset password, forgot password, 
    forgot username, and modify user details widgets.
    """
    def __init__(self, usernames: list, emails: list, cookie_name: str,
                 cookie_key: str, cookie_expiry_days: float=30.0,
                 preauthorized: list=None, weak_passwords: list=[],
                 user_credentials: dict=None) -> None:
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        usernames: list
            The set of existing usernames.
        emails: list
            The set of existing emails.
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for
            passwordless reauthentication.
        cookie_key: str
            The key to be used for hashing the signature of the JWT
            cookie.
        cookie_expiry_days: float
            The number of days before the cookie expires on the client's
            browser.
        preauthorized: list
            The list of emails of unregistered users authorized to
            register.
        weak_passwords: list
            The list of weak passwords that shouldn't be used. This isn't
            required, but is recommended.
        user_credentials: dict
            The dictionary of user credentials as {'username': username,
            'email': email, 'password': password}, with username and email
            encrypted and password hashed.
        """
        self.usernames = [username.lower() for username in usernames]
        self.emails = emails
        self.cookie_name = cookie_name
        self.cookie_key = cookie_key
        self.preauthorized = preauthorized
        self.weak_passwords = weak_passwords
        self.user_credentials = user_credentials
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

    def _check_user_info(
            self, new_email: str, new_username: str, new_password: str,
            new_password_repeat: str, preauthorization: bool) -> bool:
        """
        Check whether the registering user input is valid.
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
        if new_email in self.emails:
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
        if new_username in self.usernames:
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
        if preauthorization and new_email not in self.preauthorized:
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

        Parameters
        ----------
        username: str
            The username of the new user.
        name: str
            The name of the new user.
        password: str
            The password of the new user.
        email: str
            The email of the new user.
        preauthorization: bool
            The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        encrypt_type: str
            The type of encryption to use for the user credentials.
            'generic': Fernet symmetric encryption.
            'google': Google Cloud KMS (Key Management Service) API.
        **kwargs:
            Additional arguments for the encryption. Currently only needed
            if using 'google' encryption, in which case the following
            arguments are required:
            project_id (string): Google Cloud project ID (e.g. 'my-project').
            location_id (string): Cloud KMS location (e.g. 'us-east1').
            key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
            key_id (string): ID of the key to use (e.g. 'my-key').
            kms_credentials (google.oauth2.service_account.Credentials): The
                credentials to use for the KMS (Key Management Service).
                This could be a service account key. For example, you can
                set up a service account in the same google cloud project
                that has the KMS. This service account must be
                permissioned (at a minimum) as a "Cloud KMS CryptoKey
                Encrypter/Decrypter" in order to use the KMS.

                Example code to get the credentials (you must install
                    google-auth-oauthlib and google-auth in your environment):
                    from google.oauth2 import service_account
                    # this is the necessary scope for the KMS
                    scopes = ['https://www.googleapis.com/auth/cloudkms']
                    # this is just a file that stores the key info (the
                    # service account key, not the KMS key) in a JSON file
                    our_credentials = 'service_account_key_file.json'
                    creds = service_account.Credentials.from_service_account_file(
                        our_credentials, scopes=scopes)
        """
        st.write("_register_credentials")
        # we want to add our new username and email so they can't be
        # accidentally registered again
        self.usernames.append(username)
        st.write("usernames: ", self.usernames)
        self.emails.append(email)
        st.write("emails: ", self.emails)

        # encrypt / hash info and add to credentials dictionary
        if encrypt_type.lower() == 'generic':
            encryptor = GenericEncryptor()
        elif encrypt_type.lower() == 'google':
            encryptor = GoogleEncryptor(**kwargs)

        enc_username = encryptor.encrypt(username)
        st.write("enc_username: ", enc_username)
        enc_email = encryptor.encrypt(email)
        st.write("enc_email: ", enc_email)
        password = Hasher([password]).generate()[0]
        st.write("password: ", password)

        # store the credentials
        # note that for the generic version we get and store a key and
        # token for each username and email, while for the google version
        # we just get and store a ciphertext for each username and email
        # (the key is typically the same and is what is accessed by
        # passing in 'kms_credentials' through kwargs)
        if encrypt_type.lower() == 'generic':
            self.user_credentials = {'username': {'key': enc_username[0],
                                                  'token': enc_username[1]},
                                     'email': {'key': enc_email[0],
                                               'token': enc_email[1]},
                                     'password': password}
        elif encrypt_type.lower() == 'google':
            self.user_credentials = {'username': enc_username['ciphertext'],
                                     'email': enc_email['ciphertext'],
                                     'password': password}
        st.write("user_credentials: ", self.user_credentials)

        # if we had the name preauthorized, remove it from that list
        if preauthorization:
            st.write("preauthorized: ", self.preauthorized)
            st.write("email: ", email)
            self.preauthorized.remove(email)
            st.write("preauthorized: ", self.preauthorized)

        st.stop()

    def _check_and_register_user(
            self, new_email: str, new_username: str, new_password: str,
            new_password_repeat: str, preauthorization: bool,
            encrypt_type: str, **kwargs) -> None:
        """
        Once a new user submits their info, this is a callback to check
        the validity of their input and register them if valid.
        """
        if self._check_user_info(
                new_email, new_username, new_password, new_password_repeat,
                preauthorization):
            self._register_credentials(
                new_username, new_password, new_email, preauthorization,
                encrypt_type, **kwargs)

    def register_user(self, location: str = 'main',
                      preauthorization: bool = True,
                      encrypt_type: str = 'google',
                      **kwargs) -> Union[bool, None]:
        """
        Creates a new user registration widget.

        Note that for the generic version we get and store a key and
        token for each username and email, while for the google version
        we just get and store a ciphertext for each username and email
        (the key is typically the same and is what is accessed by
        passing in 'kms_credentials' through kwargs).

        Parameters
        ----------
        location: str
            The location of the register new user form i.e. main or
            sidebar.
        preauthorization: bool
            The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        encrypt_type: str
            The type of encryption to use for the user credentials.
            'generic': Fernet symmetric encryption.
            'google': Google Cloud KMS (Key Management Service) API.
        **kwargs:
            Additional arguments for the encryption. Currently only needed
            if using 'google' encryption, in which case the following
            arguments are required:
            project_id (string): Google Cloud project ID (e.g. 'my-project').
            location_id (string): Cloud KMS location (e.g. 'us-east1').
            key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
            key_id (string): ID of the key to use (e.g. 'my-key').
            kms_credentials (google.oauth2.service_account.Credentials): The
                credentials to use for the KMS (Key Management Service).
                This could be a service account key. For example, you can
                set up a service account in the same google cloud project
                that has the KMS. This service account must be
                permissioned (at a minimum) as a "Cloud KMS CryptoKey
                Encrypter/Decrypter" in order to use the KMS.

                Example code to get the credentials (you must install
                    google-auth-oauthlib and google-auth in your environment):
                    from google.oauth2 import service_account
                    # this is the necessary scope for the KMS
                    scopes = ['https://www.googleapis.com/auth/cloudkms']
                    # this is just a file that stores the key info (the
                    # service account key, not the KMS key) in a JSON file
                    our_credentials = 'service_account_key_file.json'
                    creds = service_account.Credentials.from_service_account_file(
                        our_credentials, scopes=scopes)
        """
        eh.clear_errors()
        if location not in ['main', 'sidebar']:
            eh.add_dev_error(
                'register_user',
                "location argument must be one of 'main' or 'sidebar'")
            return False
        if preauthorization:
            if not self.preauthorized:
                eh.add_dev_error(
                    'register_user',
                    "preauthorization argument must not be None when "
                    "preauthorization is True")
                return False
        if encrypt_type.lower() not in ['generic', 'google']:
            eh.add_dev_error(
                'register_user',
                "encrypt_type argument must be one of 'generic' or 'google'")
            return False

        if location == 'main':
            register_user_form = st.form('Register user')
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user')

        register_user_form.subheader('Register user')
        new_email = register_user_form.text_input('Email')
        new_username = register_user_form.text_input('Username').lower()
        new_password = register_user_form.text_input('Password',
                                                     type='password')
        new_password_repeat = register_user_form.text_input('Repeat password',
                                                            type='password')

        register_user_form.form_submit_button(
            'Register', on_click=self._check_and_register_user,
            args=(new_email, new_username, new_password, new_password_repeat,
                  preauthorization, encrypt_type), kwargs=kwargs)

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

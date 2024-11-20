import copy
import pandas as pd
import secrets
import streamlit as st

from datetime import datetime, timedelta
from typing import Callable, Tuple, Union

from StreamlitAuth import ErrorHandling as eh
from StreamlitAuth.BQTools import BQTools
from StreamlitAuth.Email import Email
from StreamlitAuth.Encryptor import GenericEncryptor, GoogleEncryptor
from StreamlitAuth.Hasher import Hasher
from StreamlitAuth.Validator import Validator


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
                 weak_passwords: list = [],
                 email_function: Union[Callable, str] = None,
                 email_inputs: dict = None,
                 email_creds: dict = None,
                 save_pull_function: str = None,
                 save_pull_args: dict = None) -> None:
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
            this class and want the updated list to persist. Can set this
            to None to ignore this feature.
        :param weak_passwords: The list of weak passwords that shouldn't
            be used. This isn't required, but is recommended.
        :param email_function: If we want to email the user after
            registering or updating their info, provide the method for
            email here, this can be a callable function or a string. The
            function can also return an error message as a string,
            which will be handled by the error handler.

            This variable is only necessary if you want to email the user
            in all cases and use the same method for emailing in each
            case. Otherwise, you can specify the email method in each
            individual function below.

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
            Only necessary for when email_function is not None.
            These are generic for any email method and currently include:

            website_name (str): The name of the website where the
                registration is happening.
            website_email (str) : The email that is sending the
                registration confirmation.

                Note that additional arguments will be specified in the
                individual methods below, such as the verification URL.
                You can also specify any of these arguments in the
                individual methods below, and they will override the ones
                specified here.
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
        :param save_pull_function: If you always want to use the same type
            of save or pull function, and that method is one of the
            built-in methods, you can specify that here.

            The current pre-defined types are:
                'bigquery': Saves and pulls from a BigQuery table.
        :param save_pull_args: If you have defined a save_pull_function,
            you can specify the arguments that are consistent for all
            methods here. This is a dictionary of the arguments that are
            passed to the save_pull_function.

            If save_pull_function = 'bigquery':
                bq_creds (dict): Your credentials for BigQuery, such as a
                    service account key (which would be downloaded as JSON
                    and then converted to a dict before using them here).
                project (str): The name of the Google Cloud project where
                    the BigQuery dataset is located. This should already
                    exist in GCP and have the BigQuery API enabled.
                dataset (str): The name of the dataset in BigQuery.
                    This should already have been created in BigQuery.

                Note that additional arguments will be specified in the
                individual methods below, such as the table or column
                names. You can also specify any of these arguments in the
                individual methods below, and they will override the ones
                specified here.
        """
        self.usernames_session_state = usernames_session_state
        self.emails_session_state = emails_session_state
        self.user_credentials_session_state = user_credentials_session_state
        self.preauthorized_session_state = preauthorized_session_state
        self.weak_passwords = weak_passwords
        self.email_function = email_function
        self.email_inputs = email_inputs
        self.email_creds = email_creds
        self.save_pull_function = save_pull_function
        self.save_pull_args = save_pull_args

        if not self._check_class_session_states():
            raise ValueError()
        else:
            # we need all the usernames and emails to be lowercase so the
            # user can't register with the same username or email but
            # with different capitalization
            st.session_state[self.usernames_session_state] = [
                i.lower() for i in
                st.session_state[self.usernames_session_state]]
            st.session_state[self.emails_session_state] = [
                i.lower() for i in
                st.session_state[self.emails_session_state]]

        self.save_pull_function_options = ['bigquery']
        self.save_pull_args_options = {
            'bigquery': ['bq_creds', 'project', 'dataset']}
        self.save_pull_args_function_specific = {
            'bigquery': {
                'register_user': {
                    'auth_code_pull_args':
                        ['table_name', 'email_col', 'auth_code_col'],
                    'all_locked_args':
                        ['table_name', 'email_col', 'locked_time_col'],
                    'locked_info_args':
                        ['table_name', 'email_col', 'locked_time_col'],
                    'store_locked_time_args':
                        ['table_name', 'email_col', 'locked_time_col'],
                    'all_incorrect_attempts_args':
                        ['table_name', 'email_col', 'datetime_col'],
                    'store_incorrect_attempts_args':
                        ['table_name', 'email_col', 'datetime_col'],
                    'pull_incorrect_attempts_args':
                        ['table_name', 'email_col', 'datetime_col'],
                    'cred_save_args': ['table_name']},
                'login': {
                    'password_pull_args':
                        ['table_name', 'username_col', 'password_col'],
                    'all_locked_args':
                        ['table_name', 'username_col', 'locked_time_col',
                         'unlocked_time_col'],
                    'locked_info_args':
                        ['table_name', 'username_col', 'locked_time_col',
                         'unlocked_time_col'],
                    'store_locked_time_args':
                        ['table_name', 'username_col', 'locked_time_col',
                         'unlocked_time_col'],
                    'store_unlocked_time_args':
                        ['table_name', 'username_col', 'locked_time_col',
                         'unlocked_time_col'],
                    'all_incorrect_attempts_args':
                        ['table_name', 'username_col', 'datetime_col'],
                    'store_incorrect_attempts_args':
                        ['table_name', 'username_col', 'datetime_col'],
                    'pull_incorrect_attempts_args':
                        ['table_name', 'username_col', 'datetime_col']},
                'forgot_username': {
                    'username_pull_args':
                        ['table_name', 'username_col', 'email_col']},
                'forgot_password': {
                    'username_pull_args':
                        ['table_name', 'username_col', 'email_col'],
                    'password_store_args':
                        ['table_name', 'username_col', 'password_col',
                         'datetime_col']},
                'update_user_info': {
                    'info_pull_args':
                        ['table_name', 'col_map'],
                    'info_store_args':
                        ['table_name', 'col_map']}}}

        self.email_function_options = ['sendgrid']
        self.email_input_options = {
            'sendgrid': ['website_name', 'website_email']}
        self.email_input_function_specific = {
            'sendgrid': {
                'register_user': ['verification_url']}}

        if not self._check_class_save_pull():
            raise ValueError()

        if 'stauth' not in st.session_state:
            st.session_state['stauth'] = {}
        if 'authentication_status' not in st.session_state.stauth:
            st.session_state.stauth['authentication_status'] = False
        if 'username' not in st.session_state.stauth:
            st.session_state.stauth['username'] = None

    def _check_class_session_states(self) -> bool:
        """
        Check on whether all session state inputs for exist for the class
        and are the correct type.
        """
        if self.usernames_session_state not in st.session_state or \
                not isinstance(st.session_state[self.usernames_session_state],
                               (list, set)):
            eh.add_dev_error(
                'class_instantiation',
                "usernames_session_state must be a list or set "
                "assigned to st.session_state[usernames_session_state]")
            return False
        if self.emails_session_state not in st.session_state or \
                not isinstance(st.session_state[self.emails_session_state],
                               (list, set)):
            eh.add_dev_error(
                'class_instantiation',
                "emails_session_state must be a list or set assigned to "
                "st.session_state[emails_session_state]")
            return False
        if (self.preauthorized_session_state is not None and
                (self.preauthorized_session_state not in st.session_state or
                 not isinstance(st.session_state[
                                    self.preauthorized_session_state],
                                (list, set)))):
            eh.add_dev_error(
                'class_instantiation',
                "preauthorized_session_state must be a list or set "
                "assigned to st.session_state[preauthorized_session_state]")
            return False
        return True

    def _check_class_save_pull(self) -> bool:
        """
        Check on whether the save_pull_function and save_pull_args are
        within the correct set of options.
        """
        if (self.save_pull_function is not None and
                not self.save_pull_function in
                    self.save_pull_function_options):
            eh.add_dev_error(
                'class_instantiation',
                f"save_pull_function for class instantiation must be a string "
                f"with any of the values in {self.save_pull_function_options}")
            return False
        if (self.save_pull_args is not None and
                (set(self.save_pull_args_options[self.save_pull_function]) !=
                 set(self.save_pull_args.keys()))):
            eh.add_dev_error(
                'class_instantiation',
                f"save_pull_args for class instantiation must be a dictionary "
                f"with keys "
                f"{self.save_pull_args_options[self.save_pull_function]}")
            return False
        return True

    def _check_form_inputs(self, location: str, form: str) -> bool:
        """
        Check whether the register_user inputs are within the correct set
        of options.
        """
        if location not in ['main', 'sidebar']:
            eh.add_dev_error(
                form,
                "location argument must be one of 'main' or 'sidebar'")
            return False
        return True

    def _define_save_pull_vars(
            self,
            form: str,
            target_args_name: str,
            save_pull_function: Union[Callable, str] = None,
            save_pull_args: dict = None,
            secondary_function: Union[Callable, str] = None,
            secondary_args: dict = None,
            check_args: bool = True) -> Tuple[Union[Callable, str], dict]:
        """
        Define the save or pull variables as either the class save_pull
        variables or the ones passed in the method with the method
        variables having preference. Can also compare against a secondary
        function/args instead of the class.

        We also check that the set of arguments is correct for the
        function being used, as long as the function is a predefined one.

        :param form: The name of the form that this function is being
            called from. Used for error messages.
        :param target_args_name: The name of the target args that we are
            creating/checking. Used for pulling the correct args to check
            against and for any error messages.
        :param save_pull_function: The save or pull function to use, being
            passed in from the method.
        :param save_pull_args: The save or pull arguments to use, being
            passed in from the method.
        :param secondary_function: The save or pull function to compare
            against and be used if the save_pull_function is None.
        :param secondary_args: The save or pull arguments to compare
            against and be used if the save_pull_args is None. If
            save_pull_args is not None but secondary_args has additional
            arguments, those arguments will be added to save_pull_args.
        :param check_args: Whether to check the arguments against the
            expected args for the given function. This is useful if you
            have a three-level hierarchy and you define something at the
            first level and third level. You might not want to check the
            second level since some of the arguments are defined at the
            third level.
        :return save_pull_function: The save or pull function to use. Or
            False if the args are incorrect.
        :return save_pull_args: The save or pull arguments to use. Or None
            if the args are incorrect.
        """
        if secondary_function is None:
            secondary_function = self.save_pull_function
        if secondary_args is None:
            if self.save_pull_args is not None:
                secondary_args = self.save_pull_args.copy()
            else:
                secondary_args = None

        if save_pull_function is None and secondary_function is not None:
            save_pull_function = secondary_function

        if save_pull_args is not None and secondary_args is not None:
            for key, value in secondary_args.items():
                if key not in save_pull_args:
                    save_pull_args[key] = value
        elif secondary_args is not None:
            save_pull_args = secondary_args.copy()

        if save_pull_function is None and save_pull_args is not None:
            eh.add_dev_error(
                form,
                f"for form {form}, save_pull_function must be defined if "
                f"save_pull_args '{target_args_name}' are defined")
            return False, None

        # check the save_pull_args since this could be a confusing spot
        # as we are potentially defining args both in the class
        # instantiation and in the method
        if (check_args and
                save_pull_function is not None and
                isinstance(save_pull_function, str) and
                save_pull_function in self.save_pull_function_options):
            args_to_check = self.save_pull_args_options[
                save_pull_function].copy()
            if save_pull_function in self.save_pull_args_function_specific:
                args_to_check.extend(self.save_pull_args_function_specific[
                    save_pull_function][form][target_args_name])

            if (save_pull_args is None or
                    set(args_to_check) != set(save_pull_args.keys())):
                eh.add_dev_error(
                    form,
                    f"save_pull_args for the form {form} and "
                    f"target args {target_args_name} must include the "
                    f"keys {args_to_check} and only those keys "
                    f"(either defined in the function or partially defined "
                    f"at the class level and partially in the function)")
                return False, None

        return save_pull_function, save_pull_args

    def _define_email_vars(
            self,
            form: str,
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None,
            secondary_function: Union[Callable, str] = None,
            secondary_inputs: dict = None,
            secondary_creds: dict = None,
            check_inputs: bool = False) -> Tuple[Union[Callable, str], dict,
    dict]:
        """
        Define the email variables as either the class email_inputs
        variables or the ones passed in the method with the method
        variables having preference. Can also compare against a secondary
        function/args instead of the class.

        We also check that the set of arguments is correct for the
        function being used, as long as the function is a predefined one.

        :param form: The name of the form that this function is being
            called from. Used for error messages.
        :param email_function: The email function to use, being passed in
            from the method.
        :param email_inputs: The email arguments to use, being passed in
            from the method.
        :param email_creds: The email credentials to use, being passed in
            from the method.
        :param secondary_function: The email function to compare
            against and be used if the email_function is None.
        :param secondary_inputs: The email inputs to compare
            against and be used if the email_inputs is None. If
            email_inputs is not None but secondary_inputs has additional
            arguments, those arguments will be added to email_inputs.
        :param secondary_creds: The email credentials to compare
            against and be used if the email_creds is None.
        :param check_inputs: Whether to check the inputs against the
            expected inputs for the given function. This is useful if you
            have a three-level hierarchy and you define something at the
            first level and third level. You might not want to check the
            second level since some of the arguments are defined at the
            third level.
        :return email_function: The email function to use. Or False if the
            inputs are incorrect.
        :return email_inputs: The email inputs to use. Or None if the
            inputs are incorrect.
        :return email_creds: The email credentials to use. Or None if the
            inputs are incorrect.
        """
        if secondary_function is None:
            secondary_function = self.email_function
        if secondary_inputs is None:
            if self.email_inputs is not None:
                secondary_inputs = self.email_inputs.copy()
            else:
                secondary_inputs = None
        if secondary_creds is None:
            secondary_creds = self.email_creds.copy()

        if email_function is None and secondary_function is not None:
            email_function = secondary_function
        if email_inputs is not None and secondary_inputs is not None:
            for key, value in secondary_inputs.items():
                if key not in email_inputs:
                    email_inputs[key] = value
        elif secondary_inputs is not None:
            email_inputs = secondary_inputs.copy()
        if email_creds is None and secondary_creds is not None:
            email_creds = secondary_creds

        if not ((email_function is None and email_inputs is None and
                 email_creds is None)
                or (email_function is not None and email_inputs is not None
                    and email_creds is not None)):
            eh.add_dev_error(
                form,
                f"for form {form}, either email_function, email_inputs "
                f"and email_creds must all be None or all be defined")
            return False, None, None

        # check the email_inputs since this could be a confusing spot
        # as we are potentially defining args both in the class
        # instantiation and in the method
        if (check_inputs and
                email_function is not None and
                isinstance(email_function, str) and
                email_function in self.email_function_options):
            inputs_to_check = self.email_input_options[email_function].copy()
            if email_function in self.email_input_function_specific:
                inputs_to_check.extend(self.email_input_function_specific[
                    email_function][form])

            if (email_inputs is None or
                    set(inputs_to_check) != set(email_inputs.keys())):
                eh.add_dev_error(
                    form,
                    f"email_inputs for the form {form} must include the "
                    f"keys {inputs_to_check} and only those keys "
                    f"(either defined in the function or partially defined "
                    f"at the class level and partially in the function)")
                return False, None, None

        return email_function, email_inputs, email_creds

    def _check_email_exists(
            self,
            email_function: Union[Callable, str],
            email_inputs: dict) -> bool:
        """When requiring an email for verification, check that the email
            exists and the inputs are correct."""
        if email_function is None or 'verification_url' not in email_inputs:
            eh.add_dev_error(
                'register_user',
                "email_function must be defined to verify the email "
                "since verify_email was set to True and the "
                "'verification_url' must exist in email_inputs.")
            return False
        return True

    def _define_register_user_functions_args(
            self,
            auth_code_pull_function: Union[str, Callable],
            auth_code_pull_args: dict,
            all_locked_function: str,
            all_locked_args: dict,
            locked_info_function: Union[str, Callable],
            locked_info_args: dict,
            store_locked_time_function: Union[str, Callable],
            store_locked_time_args: dict,
            all_incorrect_attempts_function: str,
            all_incorrect_attempts_args: dict,
            store_incorrect_attempts_function: Union[str, Callable],
            store_incorrect_attempts_args: dict,
            pull_incorrect_attempts_function: Union[str, Callable],
            pull_incorrect_attempts_args: dict
    ) -> Tuple[bool, Union[tuple, None]]:
        """
        Define the functions and arguments that are needed for the
            register user method with preauthorization. Uses a hierarchy
            method, where the highest level allows you to define the
            least, but if you define a lower level that will override any
            higher levels.

        Hierarchy:
        1. Class definition (self.save_pull_function, self.save_pull_args)
            a. General method definition (all_locked_function,
                                          all_locked_args)
                i. Specific method def. (locked_info_function,
                                         locked_info_args)
                ii. Specific method def. (store_locked_time_function,
                                          store_locked_time_args)
            b. General method definition (all_incorrect_attempts_function,
                                          all_incorrect_attempts_args)
                i. Specific method def. (store_incorrect_attempts_function,
                                         store_incorrect_attempts_args)
                ii. Specific method def. (pull_incorrect_attempts_function,
                                          pull_incorrect_attempts_args)
            c. General/specific method def. (auth_code_pull_function,
                                             auth_code_pull_args)
        """
        auth_code_pull_function, auth_code_pull_args = (
            self._define_save_pull_vars(
                'register_user', 'auth_code_pull_args',
                auth_code_pull_function, auth_code_pull_args))
        # this will return false for auth_code_pull_function if there was
        # an error
        if not auth_code_pull_function:
            return False, None

        all_locked_function, all_locked_args = self._define_save_pull_vars(
            'register_user', 'all_locked_args',
            all_locked_function, all_locked_args, check_args=False)
        if all_locked_function is not None and not all_locked_function:
            return False, None
        locked_info_function, locked_info_args = self._define_save_pull_vars(
            'register_user', 'locked_info_args',
            locked_info_function, locked_info_args,
            all_locked_function, all_locked_args)
        if locked_info_function is not None and not locked_info_function:
            return False, None
        store_locked_time_function, store_locked_time_args = (
            self._define_save_pull_vars(
                'register_user', 'store_locked_time_args',
                store_locked_time_function, store_locked_time_args,
                all_locked_function, all_locked_args))
        if (store_locked_time_function is not None and
                not store_locked_time_function):
            return False, None

        all_incorrect_attempts_function, all_incorrect_attempts_args = (
            self._define_save_pull_vars(
                'register_user', 'all_incorrect_attempts_args',
                all_incorrect_attempts_function, all_incorrect_attempts_args,
                check_args=False))
        if (all_incorrect_attempts_function is not None and
                not all_incorrect_attempts_function):
            return False, None
        store_incorrect_attempts_function, store_incorrect_attempts_args = (
            self._define_save_pull_vars(
            'register_user', 'store_incorrect_attempts_args',
                store_incorrect_attempts_function,
                store_incorrect_attempts_args,
                all_incorrect_attempts_function, all_incorrect_attempts_args))
        if (store_incorrect_attempts_function is not None and
                not store_incorrect_attempts_function):
            return False, None
        pull_incorrect_attempts_function, pull_incorrect_attempts_args = (
            self._define_save_pull_vars(
            'register_user', 'pull_incorrect_attempts_args',
                pull_incorrect_attempts_function, pull_incorrect_attempts_args,
                all_incorrect_attempts_function, all_incorrect_attempts_args))
        if (pull_incorrect_attempts_function is not None and
                not pull_incorrect_attempts_function):
            return False, None

        return (True,
                (auth_code_pull_function, auth_code_pull_args,
                 locked_info_function, locked_info_args,
                 store_locked_time_function, store_locked_time_args,
                 store_incorrect_attempts_function,
                 store_incorrect_attempts_args,
                 pull_incorrect_attempts_function,
                 pull_incorrect_attempts_args))

    def _check_register_user_storage_functions(
            self,
            locked_info_function: Union[str, Callable],
            store_locked_time_function: Union[str, Callable],
            store_incorrect_attempts_function: Union[str, Callable],
            pull_incorrect_attempts_function: Union[str, Callable]) -> bool:
        """
        Check whether the optional storage functions are all None or all
        not None. Either of those is fine, we just can't have some as None
        and others as not None.
        """
        if (locked_info_function is None and
            store_locked_time_function is None and
            store_incorrect_attempts_function is None and
            pull_incorrect_attempts_function is None) or \
                (locked_info_function is not None and
                 store_locked_time_function is not None and
                 store_incorrect_attempts_function is not None and
                 pull_incorrect_attempts_function is not None):
            return True
        eh.add_dev_error(
            'register_user',
            "If any of the preauthorization storage functions are used, "
            "they must all be used.")
        return False

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

    def _add_email_to_args(
            self, email: str, existing_args: dict) -> dict:
        """Add the email to existing_args."""
        if existing_args is None:
            existing_args = {}
        existing_args['email'] = email
        return existing_args

    def _pull_register_user_locked_error_handler(self, indicator: str,
                                                 value: str) -> bool:
        """ Records any errors from pulling the latest locked account
            times."""
        if indicator == 'dev_error':
            eh.add_dev_error(
                'register_user',
                "There was an error pulling the latest account lock times. "
                "Error: " + value)
            return False
        return True

    def _pull_register_user_locked_info(
            self,
            email: str,
            locked_info_function: Union[str, Callable],
            locked_info_args: dict) -> Tuple[bool, Union[tuple, None]]:
        """
        Pull the most recent locked times from the database.

        :param email: The email to check.
        :param locked_info_function: The function to pull the locked
            information associated with the email. This can be a
            callable function or a string.

            The function should pull in locked_info_args, which can be
            used for things like accessing and pulling from a database.
            At a minimum, a callable function should take 'email' as
            one of the locked_info_args, but can include other arguments
            as well.
            A callable function should return:
            - A tuple of an indicator and a value
            - The indicator should be either 'dev_error' or 'success'.
            - The value should be a string that contains the error
                message when the indicator is 'dev_error' and
                latest_lock_datetime when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the locked datetimes from a BigQuery
                    table.
                    This pre-defined version will look for a table with
                    two columns corresponding to email and locked_time
                    (see locked_info_args below for how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that writes
                    to a table set up in the same way.
        :param locked_info_args: Arguments for the locked_info_function.
            This should not include 'email' since that will
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
            email_col (str): The name of the column in the BigQuery
                table that contains the emails.
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.
        :return: Tuple with the first value as True if the data was pulled
            and False if there was an error, and the second value will be
            latest_lock_datetime if the data was pulled successfully,
            and None if there was an error.
        """
        # add the email to the arguments for the locked info
        locked_info_args = self._add_email_to_args(
            email, locked_info_args)
        if isinstance(locked_info_function, str):
            if locked_info_function.lower() == 'bigquery':
                db = BQTools()
                indicator, value = db.pull_register_user_locked_info_bigquery(
                    **locked_info_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The locked_info_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = locked_info_function(**locked_info_args)
        if self._pull_register_user_locked_error_handler(indicator, value):
            return True, value
        return False, None

    def _check_locked_account_register_user(
            self,
            email: str,
            locked_info_function: Union[str, Callable] = None,
            locked_info_args: dict = None,
            locked_hours: int = 24) -> bool:
        """
        Check if we have a locked account for the given email.

        This should include checking whether the account is locked in
        the session_state, which always happens, and checking if there is
        a lock stored elsewhere, such as in a database. The checking of
        the lock elsewhere is not required for this function to run, but
        is HIGHLY RECOMMENDED since the session state can be easily
        cleared by the user, which would allow them to bypass the lock.

        :param email: The email to check.
        :param locked_info_function: The function to pull the locked
            information associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param locked_info_args: Arguments for the locked_info_function.
            See the docstring for register_user for more information.
        :param locked_hours: The number of hours that the account should
            be locked for after a certain number of failed login attempts.
            The desired number of incorrect attempts is set elsewhere.
        :return: True if the account is LOCKED (or there is an error),
            False if the account is UNLOCKED.
        """
        # if we have a locked_info_function, check that;
        # otherwise just use what we have saved in the session_state
        if locked_info_function is not None:
            # pull the latest locked and unlocked times
            pull_worked, value = self._pull_register_user_locked_info(
                email, locked_info_function, locked_info_args)
            if pull_worked:
                latest_lock = value
            else:
                return True
        else:
            if ('register_user_lock' in st.session_state.stauth and
                    email in st.session_state.stauth[
                        'register_user_lock'].keys()):
                latest_lock = max(st.session_state.stauth[
                                      'register_user_lock'][email])
            else:
                latest_lock = None
        return self._is_account_locked(
            latest_lock, None, locked_hours, 'register_user')

    def _rename_auth_code_pull_args(self, auth_code_pull_args: dict) -> dict:
        """Update the target and reference columns and reference value."""
        auth_code_pull_args['reference_col'] = auth_code_pull_args[
            'email_col']
        auth_code_pull_args['reference_value'] = auth_code_pull_args[
            'email']
        auth_code_pull_args['target_col'] = auth_code_pull_args['auth_code_col']
        del auth_code_pull_args['email_col']
        del auth_code_pull_args['email']
        del auth_code_pull_args['auth_code_col']
        return auth_code_pull_args

    def _auth_code_pull_error_handler(self, indicator: str,
                                      value: str) -> bool:
        """ Records any errors from the authorization code pulling
            process."""
        if indicator == 'dev_error':
            eh.add_dev_error(
                'register_user',
                "There was an error checking the user's authorization code. "
                "Error: " + value)
            return False
        elif indicator == 'user_error':
            eh.add_user_error(
                'register_user',
                "Incorrect email or authorization code.")
            return False
        return True

    def _auth_code_verification_error_handler(
            self, verified: Union[bool, tuple]) -> bool:
        """Check if the authorization code was verified and record an
            error if not."""
        if isinstance(verified, tuple):
            # if we have a tuple, that means we had a 'dev_errors'
            # issue, which should be handled accordingly
            eh.add_dev_error(
                'register_user',
                "There was an error checking the user's authorization code. "
                "Error: " + verified[1])
            return False
        elif verified:
            return True
        else:
            eh.add_user_error(
                'register_user',
                "Incorrect email or authorization code.")
            return False

    def _check_auth_code(
            self,
            auth_code: str,
            email: str,
            auth_code_pull_function: Union[str, Callable],
            auth_code_pull_args: dict = None) -> bool:
        """
        Pulls the expected authorization code and checks the validity of
        the entered authorization code.

        :param auth_code: The entered authorization code.
        :param email: The entered email.
        :param auth_code_pull_function: The function to pull the hashed
            authorization code associated with the email. This can be a
            callable function or a string.

            At a minimum, a callable function should take 'email' as
            an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error'
                or 'success'.
             - The value should be a string that contains the error
                message when the indicator is 'dev_error', None when the
                indicator is 'user_error', and the hashed authorization
                code when the indicator is 'success'. It is None with
                'user_error' since we will handle that in the calling
                function and create a user_error that tells the user that
                the email or authorization code is incorrect.

            The current pre-defined function types are:
                'bigquery': Pulls the authorization code from a BigQuery
                table.
        :param auth_code_pull_args: Arguments for the
            auth_code_pull_function. This should not include 'email'
            since that will automatically be added here based on the
            user's input.

            If using 'bigquery' as your auth_code_pull_function, the
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
            auth_code_col (str): The name of the column in the BigQuery
                table that contains the authorization codes.
        """
        # add the email to the arguments for the authorization code pull
        # function
        auth_code_pull_args = self._add_email_to_args(
            email, auth_code_pull_args)
        # pull the authorization code
        if isinstance(auth_code_pull_function, str):
            if auth_code_pull_function.lower() == 'bigquery':
                auth_code_pull_args = self._rename_auth_code_pull_args(
                    auth_code_pull_args)
                db = BQTools()
                indicator, value = db.pull_value_based_on_other_col_value(
                    **auth_code_pull_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The auth_code_pull_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = auth_code_pull_function(**auth_code_pull_args)

        # only continue if we didn't have any issues getting the
        # authorization code
        if self._auth_code_pull_error_handler(indicator, value):
            verified = Hasher([auth_code]).check([value])[0]
            # we can have errors here if the authorization code doesn't
            # match or there is an issue running the check
            return self._auth_code_verification_error_handler(verified)
        return False

    def _store_incorrect_auth_code_attempts_handler(
            self,
            email: str,
            store_incorrect_attempts_function: Union[str, Callable],
            store_incorrect_attempts_args: dict) -> bool:
        """
        Attempts to store the incorrect attempt time and email, deals
        with any errors and updates the session_state as necessary.

        :param email: The email to store the lock time for.
        :param store_incorrect_attempts_function: The function to store
            the incorrect attempts associated with the email. This can
            be a callable function or a string. See the docstring for
            register_user for more information.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. See the docstring for
            register_user for more information.

        :return: False if any errors, True if no errors.
        """
        if 'failed_auth_attempts' not in st.session_state.stauth:
            st.session_state.stauth['failed_auth_attempts'] = {}
        if email not in st.session_state.stauth[
                'failed_auth_attempts'].keys():
            st.session_state.stauth['failed_auth_attempts'][email] = []
        # append the current datetime
        st.session_state.stauth['failed_auth_attempts'][email].append(
            datetime.utcnow())

        if store_incorrect_attempts_function is not None:
            error = self._store_incorrect_attempt(
                email, store_incorrect_attempts_function,
                store_incorrect_attempts_args, 'register_user')
            return self._incorrect_attempts_error_handler(
                error, 'register_user')
        else:
            return True

    def _check_too_many_auth_code_attempts(
            self,
            email: str,
            pull_incorrect_attempts_function: Union[str, Callable] = None,
            pull_incorrect_attempts_args: dict = None,
            locked_hours: int = 24,
            incorrect_attempts: int = 10) -> bool:
        """
        Check if we have too many authorization code attempts for the
        given email.

        :param email: The email to check.
        :param pull_incorrect_attempts_function: The function to pull the
            incorrect attempts associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. See the docstring for
            register_user for more information.
        :param locked_hours: The number of hours that the account should
            be locked for after a certain number of failed authorization
            code attempts.
        :param incorrect_attempts: The number of incorrect attempts
            allowed before the account is locked.

        :return: True if account should be locked, False if account should
            be unlocked.
        """
        # first try pulling the data from a database if we have one we
        # are using for this purpose
        if pull_incorrect_attempts_function is not None:
            attempts_pull_worked, attempts = self._pull_incorrect_attempts(
                email, 'register_user',
                pull_incorrect_attempts_function, pull_incorrect_attempts_args)
        else:
            # if not, just use the session_state
            if ('failed_auth_attempts' in st.session_state.stauth and
                    email in st.session_state.stauth[
                        'failed_auth_attempts'].keys()):
                attempts = pd.Series(st.session_state.stauth[
                                         'failed_auth_attempts'][email])
            else:
                attempts = None
            attempts_pull_worked = True

        if attempts_pull_worked and attempts is not None:
            # sort attempts by datetime, starting with the most recent
            attempts = attempts.sort_values(ascending=False)
            # count the number of attempts in the last locked_hours
            recent_attempts = attempts[
                attempts > datetime.utcnow() - timedelta(hours=locked_hours)]
            if len(recent_attempts) >= incorrect_attempts:
                eh.add_user_error(
                    'register_user',
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
                'register_user',
                "Your account is locked. Please try again later.")
            return True

    def _store_lock_time_register_user(
            self,
            email: str,
            store_function: Union[str, Callable],
            store_args: dict) -> Union[None, str]:
        """
        Store the locked or unlocked time associated with the email.

        :param email: The email to store the lock time for.
        :param store_function: The function to store the locked datetime
            associated with the email. Thi can be a callable function or a
            string.

            The function should pull in store_args, which can be used for
            things like accessing and storing to a database. At a minimum,
            a callable function should take 'email' as one of the
            store_args, but can include other arguments as well. A
            callable function can return an error message as a string,
            which our error handler will handle.

            The current pre-defined function types are:
                'bigquery': Stores the locked datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with two columns corresponding to email and
                    locked_time (see store_args below for how to define
                    there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_args: Arguments for the store_function. This should
            not include 'email' since that will automatically be added
            here. Instead, it should include things like database name,
            table name, credentials to log into the database, etc.

            If using 'bigquery' as your store_function, the following
            arguments are required:

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
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.

        :return: None if there is no error, a string error message if
            there is an error.
        """
        store_args = self._add_email_to_args(email, store_args)
        if isinstance(store_function, str):
            if store_function.lower() == 'bigquery':
                db = BQTools()
                error = db.store_lock_times(**store_args)
            else:
                error = ("The store_function method is not recognized. The "
                         "available options are: 'bigquery' or a callable "
                         "function.")
        else:
            error = store_function(**store_args)
        return error

    def _store_auth_code_lock_time_handler(
            self,
            email: str,
            store_locked_time_function: Union[str, Callable],
            store_locked_time_args: dict) -> None:
        """
        Attempts to store the lock time, deals with any errors and
        updates the session_state as necessary.

        :param email: The email to store the lock time for.
        :param store_locked_time_function: The function to store the
            locked times associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param store_locked_time_args: Arguments for the
            store_locked_times_function. See the docstring for
            register_user for more information.
        """
        if 'register_user_lock' not in st.session_state.stauth:
            st.session_state.stauth['register_user_lock'] = {}
        if email not in st.session_state.stauth[
            'register_user_lock'].keys():
            st.session_state.stauth['register_user_lock'][email] = []
        # append the current datetime
        st.session_state.stauth['register_user_lock'][email].append(
            datetime.utcnow())

        if store_locked_time_function is not None:
            error = self._store_lock_time_register_user(
                email, store_locked_time_function, store_locked_time_args)
            self._lock_time_save_error_handler(error, 'register_user')

    def _check_preauthorization_code(
            self,
            new_email: str,
            auth_code: str,
            auth_code_pull_function: Union[str, Callable],
            auth_code_pull_args: dict,
            incorrect_attempts: int,
            locked_hours: int,
            locked_info_function: Union[str, Callable],
            locked_info_args: dict,
            store_locked_time_function: Union[str, Callable],
            store_locked_time_args: dict,
            store_incorrect_attempts_function: Union[str, Callable],
            store_incorrect_attempts_args: dict,
            pull_incorrect_attempts_function: Union[str, Callable],
            pull_incorrect_attempts_args: dict) -> bool:
        """
        Check to see if the account is locked and, if not, if the
        preauthorization code is correct. If not, store the incorrect
        attempt and lock the account if we have too many incorrect
        attempts.

        :param new_email: The new user's email.
        :param auth_code: The entered authorization code.
        :param auth_code_pull_function: The function to pull the
            authorization code associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param auth_code_pull_args: Arguments for the
            auth_code_pull_function. See the docstring for register_user
            for more information.
        :param incorrect_attempts: The number of incorrect attempts
            allowed before the account is locked.
        :param locked_hours: The number of hours the account is locked
            after exceeding the number of incorrect attempts.

        The following parameters are all associated with preauthorization
        and the pattern of storing incorrect registration attempts to a
        database, as well as storing the times of an email being locked.
        If too many incorrect attempts occur at registration, the account
        is locked for locked_hours.
        Unlike with login, we don't have an unlock time, since that just
        means the user was able to register, which should only happen
        once.
        This database pattern isn't required, but is HIGHLY RECOMMENDED.
        If not used, the session_state will still record incorrect
        registration attempts and if an account is locked, but that
        can easily be disregarded by refreshing the website.
        Only necessary if preauthorization is True.

        :param locked_info_function: The function to pull the locked
            information associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param locked_info_args: Arguments for the locked_info_function.
            See the docstring for register_user for more information.
        :param store_locked_time_function: The function to store the
            locked times associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param store_locked_time_args: Arguments for the
            store_locked_times_function. See the docstring for
            register_user for more information.
        :param store_incorrect_attempts_function: The function to store
            the incorrect attempts associated with the email. This can
            be a callable function or a string. See the docstring for
            register_user for more information.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. See the docstring for
            register_user for more information.
        :param pull_incorrect_attempts_function: The function to pull the
            incorrect attempts associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. See the docstring for
            register_user for more information.

        :return: True if the account is authorized to register, False if
            the account is locked or the authorization code is incorrect.
        """
        # first see if the account should be locked
        if self._check_locked_account_register_user(
                new_email, locked_info_function, locked_info_args,
                locked_hours):
            return False
        else:
            # only continue if the authorization code is correct
            if self._check_auth_code(auth_code,
                                     new_email,
                                     auth_code_pull_function,
                                     auth_code_pull_args):
                return True
            else:
                if (not self._store_incorrect_auth_code_attempts_handler(
                        new_email, store_incorrect_attempts_function,
                        store_incorrect_attempts_args)
                        or
                        self._check_too_many_auth_code_attempts(
                            new_email,
                            pull_incorrect_attempts_function,
                            pull_incorrect_attempts_args,
                            locked_hours, incorrect_attempts)):
                    self._store_auth_code_lock_time_handler(
                        new_email, store_locked_time_function,
                        store_locked_time_args)
                return False

    def _register_credentials(self, username: str, password: str,
                              email: str, preauthorization: bool,
                              email_code: str = None) -> None:
        """
        Adds to credentials dictionary the new user's information.

        :param username: The username of the new user.
        :param password: The password of the new user.
        :param email: The email of the new user.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param verify_email: If we want to validate the user's email, the
            email_code should be supplied here.
        """
        # we want to add our new username and email to the session state,
        # so they can't be accidentally registered again
        st.session_state[self.usernames_session_state].append(username)
        st.session_state[self.emails_session_state].append(email)

        # hash password
        password = Hasher([password]).generate()[0]

        if email_code is not None:
            # hash for storage
            hashed_email_code = Hasher([email_code]).generate()[0]
            # store the credentials
            st.session_state[self.user_credentials_session_state] = {
                'username': username,
                'email': email,
                'password': password,
                'email_code': hashed_email_code,
                'email_verified': False}
        else:
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

    def _get_message_subject(self, message_type: str,
                             website_name: str) -> str:
        if message_type == 'register_user':
            return f"""{website_name}: Thank You for Registering"""
        elif message_type == 'forgot_username':
            return f"""{website_name}: Your Username"""
        elif message_type == 'forgot_password':
            return f"""{website_name}: Your Password Reset"""
        elif message_type == 'update_user_info':
            return f"""{website_name}: Account Information Update"""

    def _create_full_verification_url(self,
                                      verification_url: str,
                                      email_code: str,
                                      user_email: str) -> str:
        """Add the code and email to the verification url."""
        # see if there are any ? already in the url, meaning there
        # are already query params in the url
        if '?' in verification_url:
            url_with_params = verification_url + f"&email_address={user_email}"
        else:
            # for query params, we don't want the url to end with a /
            if verification_url[-1] == "/":
                verification_url = verification_url[:-1]
            url_with_params = verification_url + f"?email_address={user_email}"
        url_with_params = url_with_params + f"&email_code={email_code}"
        return url_with_params

    def _get_message_body(self,
                          message_type: str, website_name: str,
                          username: str = None, website_email: str = None,
                          password: str = None, info_type: str = None,
                          verification_url: str = None,
                          email_code: str = None,
                          user_email: str = None) -> str:
        if message_type == 'register_user':
            message_body = \
                (f"""Thank you for registering for {website_name}!\n\n
                 You have successfully registered with the username: 
                 {username}.\n\n""")
            if verification_url is not None:
                url_with_params = self._create_full_verification_url(
                    verification_url, email_code, user_email)
                message_body = message_body + \
                    (f"""Please click the following link to verify your email:
                     {url_with_params}.\n\n""")
            message_body = message_body + \
                (f"""If you did not register or you have any questions, 
                please contact us at {website_email}.""")
        elif message_type == 'forgot_username':
            message_body = \
                (f"""You requested your username for {website_name}.\n\n
                 Your username is: {username}.\n\n
                 If you did not request your username or you have any
                 questions, please contact us at {website_email}.""")
        elif message_type == 'forgot_password':
            message_body = \
                (f"""You requested a password reset for {website_name}.\n\n
                 Your new password is: {password} .\n\n
                 If you did not request a password reset or you have any
                 questions, please contact us at {website_email}.""")
        elif message_type == 'update_user_info':
            message_body = \
                (f"""You have updated your {info_type} at {website_name}.\n\n
                 If you did not request an update or you have any
                 questions, please contact us at {website_email}.""")
        return message_body

    def _check_email_type(self, message_type: str) -> bool:
        """
        Check on whether the message_type for an email is within the
        correct set of options.
        """
        if not isinstance(message_type, str) or \
                message_type not in ['register_user', 'forgot_username',
                                     'forgot_password', 'update_user_info']:
            eh.add_dev_error(
                message_type,
                "The message_type is not recognized. The available "
                "options are: 'register_user','forgot_username', "
                "'forgot_password' or 'update_user_info'.")
            return False
        return True

    def _check_email_inputs(self, website_name: str = None,
                            website_email: str = None,
                            verification_url: str = None) -> bool:
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
        if (verification_url is not None and
                not isinstance(verification_url, str)):
            eh.add_dev_error(
                'register_user',
                "verification_url must be a string.")
            return False
        return True

    def _email_error_handler(self, message_type: str, error: str) -> bool:
        """
        Records any errors from the email sending process.
        """
        if error is not None:
            eh.add_dev_error(
                message_type,
                "There was an error sending the email. "
                "Error: " + error)
            return False
        return True

    def _send_user_email(
            self,
            message_type: str,
            email_inputs: dict,
            user_email: str,
            email_function: Union[callable, str],
            email_creds: dict = None,
            username: str = None,
            password: str = None,
            info_type: str = None,
            email_code: str = None) -> None:
        """
        Send an email to the user. Can be used for user registration,
        a forgotten username or password, or a user info update (updating
        email, username or password).

        :param message_type: The type of message we are sending. Can be
            'register_user', 'forgot_username', 'forgot_password' or
            'update_user_info'.
        :param email_inputs: The inputs for the email sending process.
            These are generic for any email method and currently include:

            website_name (str): The name of the website where the
                registration is happening.
            website_email (str) : The email that is sending the
                registration confirmation.
            verification_url (str): The base email for verification, not
                including the verification code parameter. Required if
                verifying the email. For example, it could be something
                like 'www.verifymyemail.com/'. We will add the
                verification code based on
        :param user_email: The user's email.
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
            the docstring for register_user for more information.
        :param username: The user's username.
        :param password: The user's password. Only necessary if
            message_type is 'forgot_password'.
        :param info_type: The type of information being updated. Only
            necessary if message_type is 'update_user_info'.
        :param email_code: The email verification code. Only necessary if
            message_type is 'register_user' and we want to verify the
            user's email (verify_email is True in register_user method).
        """
        if (self._check_email_inputs(**email_inputs) and
                self._check_email_type(message_type)):
            subject = self._get_message_subject(
                message_type, email_inputs['website_name'])
            if email_code is None:
                email_inputs['verification_url'] = None
            body = self._get_message_body(
                message_type, email_inputs['website_name'], username,
                email_inputs['website_email'], password, info_type,
                email_inputs['verification_url'], email_code, user_email)
            email_handler = Email(user_email, subject, body,
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
                    error = ("The email_function method is not recognized. "
                             "The available options are: 'gmail' or "
                             "'sendgrid'.")
            else:
                error = email_function(**email_creds)
            if self._email_error_handler(message_type, error):
                eh.clear_errors()

    def _check_and_register_user(
            self,
            email_text_key: str,
            username_text_key: str,
            password_text_key: str,
            repeat_password_text_key: str,
            auth_code_key: str,
            preauthorization: bool,
            verify_email: bool,
            email_function: Union[callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None,
            cred_save_function: Union[Callable, str] = None,
            cred_save_args: dict = None,
            auth_code_pull_function: Union[str, Callable] = 'bigquery',
            auth_code_pull_args: dict = None,
            incorrect_attempts: int = 10,
            locked_hours: int = 24,
            locked_info_function: Union[str, Callable] = None,
            locked_info_args: dict = None,
            store_locked_time_function: Union[str, Callable] = None,
            store_locked_time_args: dict = None,
            store_incorrect_attempts_function: Union[
                str, Callable] = None,
            store_incorrect_attempts_args: dict = None,
            pull_incorrect_attempts_function: Union[str, Callable] = None,
            pull_incorrect_attempts_args: dict = None) -> None:
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
        :param auth_code_key: The session state name to access the new
            user's authentication code if preauthorization is required.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param verify_email: If True, the user must verify their email
            so we will create a random verification code. If saving the
            credentials, it can save there, as well as an indicator that
            the email is not yet verified.The user must also be emailed in
            this case and the email will contain a URL with the
            verification code as a parameter. Then you can verify this
            parameter using the verify_email method in Verification.
        :param email_function: If we want to email the user after
            registering, provide the function (callable) or method (str)
            for email here. See the docstring for register_user for more
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
            Only necessary for when email_function is not None. See the
            docstring for register_user for more information.
        :param email_creds: The credentials to use for the email API. Only
            necessary if email_function is not None. See the
            docstring for register_user for more information.
        :param cred_save_function: The function to save the credentials.
            See the docstring for register_user for more information.
        :param cred_save_args: The arguments to pass to the
            cred_save_function. Only necessary if cred_save_function is
            not none. See the docstring for register_user for more
            information.
        :param auth_code_pull_function: The function to pull the
            authorization code associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param auth_code_pull_args: Arguments for the
            auth_code_pull_function. See the docstring for register_user
            for more information.
        :param incorrect_attempts: The number of incorrect attempts
            allowed before the account is locked.
        :param locked_hours: The number of hours the account is locked
            after exceeding the number of incorrect attempts.

        The following parameters are all associated with preauthorization
        and the pattern of storing incorrect registration attempts to a
        database, as well as storing the times of an email being locked.
        If too many incorrect attempts occur at registration, the account
        is locked for locked_hours.
        Unlike with login, we don't have an unlock time, since that just
        means the user was able to register, which should only happen
        once.
        This database pattern isn't required, but is HIGHLY RECOMMENDED.
        If not used, the session_state will still record incorrect
        registration attempts and if an account is locked, but that
        can easily be disregarded by refreshing the website.
        Only necessary if preauthorization is True.

        :param locked_info_function: The function to pull the locked
            information associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param locked_info_args: Arguments for the locked_info_function.
            See the docstring for register_user for more information.
        :param store_locked_time_function: The function to store the
            locked times associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param store_locked_time_args: Arguments for the
            store_locked_times_function. See the docstring for
            register_user for more information.
        :param store_incorrect_attempts_function: The function to store
            the incorrect attempts associated with the email. This can
            be a callable function or a string. See the docstring for
            register_user for more information.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. See the docstring for
            register_user for more information.
        :param pull_incorrect_attempts_function: The function to pull the
            incorrect attempts associated with the email. This can be a
            callable function or a string. See the docstring for
            register_user for more information.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. See the docstring for
            register_user for more information.
        """
        new_email = st.session_state[email_text_key]
        new_username = st.session_state[username_text_key]
        new_password = st.session_state[password_text_key]
        new_password_repeat = st.session_state[repeat_password_text_key]
        if auth_code_key in st.session_state:
            auth_code = st.session_state[auth_code_key]
        else:
            auth_code = ''

        if self._check_register_user_info(
                new_email, new_username, new_password, new_password_repeat,
                preauthorization):
            if preauthorization:
                creds_verified = self._check_preauthorization_code(
                    new_email, auth_code, auth_code_pull_function,
                    auth_code_pull_args, incorrect_attempts, locked_hours,
                    locked_info_function, locked_info_args,
                    store_locked_time_function, store_locked_time_args,
                    store_incorrect_attempts_function,
                    store_incorrect_attempts_args,
                    pull_incorrect_attempts_function,
                    pull_incorrect_attempts_args)
            else:
                creds_verified = True

            if creds_verified:
                if verify_email:
                    validator = Validator()
                    email_code = validator.generate_random_password(
                        self.weak_passwords)
                else:
                    email_code = None
                self._register_credentials(
                    new_username, new_password, new_email, preauthorization,
                    email_code)
                # we can either try to save credentials and email, save
                # credentials and not email, just email, or none of the
                # above
                if cred_save_function is not None:
                    error = self._save_user_credentials(
                        cred_save_function, cred_save_args)
                    if self._cred_save_error_handler(error):
                        if email_function is not None:
                            self._send_user_email(
                                'register_user', email_inputs,
                                new_email, email_function, email_creds,
                                new_username, email_code=email_code)
                        else:
                            eh.clear_errors()
                elif email_function is not None:
                    self._send_user_email(
                        'register_user', email_inputs, new_email,
                        email_function, email_creds, new_username,
                        email_code=email_code)
                else:
                    # get rid of any errors, since we have successfully
                    # registered
                    eh.clear_errors()

    def register_user(
            self,
            location: str = 'main',
            preauthorization: bool = False,
            verify_email: bool = False,
            email_text_key: str = 'register_user_email',
            username_text_key: str = 'register_user_username',
            password_text_key: str = 'register_user_password',
            repeat_password_text_key: str =
              'register_user_repeat_password',
            auth_code_key: str = 'register_user_auth_code',
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None,
            cred_save_function: Union[Callable, str] = None,
            cred_save_args: dict = None,
            auth_code_pull_function: Union[str, Callable] = 'bigquery',
            auth_code_pull_args: dict = None,
            incorrect_attempts: int = 10,
            locked_hours: int = 24,
            all_locked_function: str = None,
            all_locked_args: dict = None,
            locked_info_function: Union[str, Callable] = None,
            locked_info_args: dict = None,
            store_locked_time_function: Union[str, Callable] = None,
            store_locked_time_args: dict = None,
            all_incorrect_attempts_function: str = None,
            all_incorrect_attempts_args: dict = None,
            store_incorrect_attempts_function: Union[
                str, Callable] = None,
            store_incorrect_attempts_args: dict = None,
            pull_incorrect_attempts_function: Union[str, Callable] = None,
            pull_incorrect_attempts_args: dict = None) -> None:
        """
        Creates a new user registration widget.

        :param location: The location of the register new user form i.e.
            main or sidebar.
        :param preauthorization: The preauthorization requirement.
            True: user must be preauthorized to register.
            False: any user can register.
        :param verify_email: If True, the user must verify their email
            so we will create a random verification code. If saving the
            credentials, it can save there, as well as an indicator that
            the email is not yet verified.The user must also be emailed in
            this case and the email will contain a URL with the
            verification code as a parameter. Then you can verify this
            parameter using the verify_email method in Verification.
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
        :param auth_code_key: The key for the authorization code text
            input on the registration form. We attempt to default to a
            unique key, but you can put your own in here if you want to
            customize it or have clashes with other keys/forms.
        :param email_function: If we want to email the user after
            registering, provide the method for email here, this can be a
            callable function or a string. The function can also return an
            error message as a string, which will be handled by the error
            handler.

            Only necessary if a) we want to email the user and b)
            email_function was not defined in the class instantiation. If
            we defined the email method in the class instantiation and we
            provide another here, the one here will override the one in
            the class instantiation. This is required if we set
            verify_email to True.

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
            Only necessary for when email_function is not None.
            These are generic for any email method and currently include:

            website_name (str): The name of the website where the
                registration is happening.
            website_email (str) : The email that is sending the
                registration confirmation.
            verification_url (str): The base email for verification, not
                including the verification code parameter. Required if
                verify_email is True. For example, it could be something
                like 'www.verifymyemail.com'. We will add the
                verification code. Note that for st.query_params to pull
                out the query parameters, we need the url to end without
                a "/", so we remove any trailing "/".
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
        :param cred_save_function: A function (callable) or pre-defined
            function type (str) to save the credentials.

            The current pre-defined function types are:
                'bigquery': Saves the credentials to a BigQuery table.

            Only necessary if a) we want to save the credentials and b)
            the save_pull_function variable was not defined in the class
            instantiation. If we defined the save_pull_function method in
            the class instantiation and we provide a value here, the one
            here will override the one in the class instantiation.

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

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name must be defined here.
        :param auth_code_pull_function: The function to pull the
            authorization code associated with the email. This can be a
            callable function or a string.

            Only necessary if preauthorization is True.

            Only necessary to define here if the save_pull_function was
            not defined in the class instantiation. But if defined here,
            it will override the class instantiation.

            At a minimum, a callable function should take 'email' as
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
                email or authorization code was incorrect.

            The current pre-defined function types are:
                'bigquery': Pulls the code from a BigQuery table. It
                    performs a basic SQL lookup to see if there are any
                    codes associated with the given email and, if
                    so, returns that (hashed) code.
        :param auth_code_pull_args: Arguments for the
            auth_code_pull_function.

            Only necessary if auth_code_pull_function is defined when you
            call this method.

            If using 'bigquery' as your auth_code_pull_function, the
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
            auth_code_col (str): The name of the column in the BigQuery
                table that contains the authorization codes.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, email_col and auth_code_col must be
            defined here.
        :param incorrect_attempts: The number of incorrect attempts
            allowed before the account is locked. Only necessary if
            preauthorization is True.
        :param locked_hours: The number of hours the account is locked
            after exceeding the number of incorrect attempts. Only
            necessary if preauthorization is True.

        The following parameters are all associated with preauthorization
        and the pattern of storing incorrect registration attempts to a
        database, as well as storing the times of an email being locked.
        If too many incorrect attempts occur at registration, the account
        is locked for locked_hours.
        Unlike with login, we don't have an unlock time, since that just
        means the user was able to register, which should only happen
        once.
        This database pattern isn't required, but is HIGHLY RECOMMENDED.
        If not used, the session_state will still record incorrect
        registration attempts and if an account is locked, but that
        can easily be disregarded by refreshing the website.
        Only necessary if preauthorization is True.

        :param all_locked_function: Since all the lock-type functions
            below behave similarly, you can define all of them at once
            here if the input is a string. For example, you could say
            all_locked_function='bigquery'. However, since each function
            behaves somewhat differently at the detailed level, you cannot
            supply a function here.

            This replaces the need to define locked_info_function and
            store_locked_time_function.

            Only necessary if the save_pull_function was not defined
            in the class instantiation. But if defined here, it will
            override the class instantiation.

            The current pre-defined function types are:
                'bigquery': Pulls and stores the locked datetimes from a
                BigQuery table.
        :param all_locked_args: If all_locked_function is defined, you
            can supply the arguments for the type of function here. For
            example, if using 'bigquery', you would supply:

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
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.

            Only necessary if all_locked_function is defined when you
            call this method.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, email_col and locked_time_col must be
            defined here.
        :param locked_info_function: The function to pull the locked
            information associated with the email. This can be a
            callable function or a string.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b) all_locked_function
            was not defind in this method. But if defined here, it will
            override either of those.

            The function should pull in locked_info_args, which can be
            used for things like accessing and pulling from a database.
            At a minimum, a callable function should take 'email' as
            one of the locked_info_args, but can include other arguments
            as well.
            A callable function should return:
            - A tuple of an indicator and a value
            - The indicator should be either 'dev_error' or 'success'.
            - The value should be a string that contains the error
                message when the indicator is 'dev_error' and
                latest_lock_datetime when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the locked datetimes from a BigQuery
                    table.
                    This pre-defined version will look for a table with
                    two columns corresponding to email and locked_time
                    (see locked_info_args below for how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that writes
                    to a table set up in the same way.
        :param locked_info_args: Arguments for the locked_info_function.
            This should not include 'email' since that will
            automatically be added here. Instead, it should include things
            like database name, table name, credentials to log into the
            database, etc.

            Only necessary if locked_info_function is defined when you
            call this method.

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
            email_col (str): The name of the column in the BigQuery
                table that contains the emails.
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, email_col and locked_time_col must be
            defined here.
        :param store_locked_time_function: The function to store the
            locked datetime associated with the email. This can be a
            callable function or a string.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b) all_locked_function
            was not defind in this method. But if defined here, it will
            override either of those.

            The function should pull in store_locked_time_args, which can
            be used for things like accessing and storing to a database.
            At a minimum, a callable function should take 'email' as
            one of the locked_info_args, but can include other arguments
            as well. A callable function can return an error message
            as a string, which our error handler will handle.

            The current pre-defined function types are:
                'bigquery': Stores the locked datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with two columns corresponding to username and
                    locked_time (see store_locked_time_args below for how
                    to define there). Note that if using 'bigquery' here,
                    in our other database functions, you should also be
                    using the 'bigquery' option or using your own method
                    that pulls from a table set up in the same way.
        :param store_locked_time_args: Arguments for the
            store_locked_time_function. This should not include 'email'
            since that will automatically be added here. Instead, it
            should include things like database name, table name,
            credentials to log into the database, etc.

            Only necessary if store_locked_time_function is defined when
            you call this method.

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
            email_col (str): The name of the column in the BigQuery
                table that contains the emails.
            locked_time_col (str): The name of the column in the BigQuery
                table that contains the locked_times.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, email_col and locked_time_col must be
            defined here.
        :param all_incorrect_attempts_function: Since all the
            incorrect attempts-type functions below behave similarly,
            you can define all of them at once here if the input is a
            string. For example, you could say
            all_incorrect_attempts_function='bigquery'. However, since
            each function behaves somewhat differently at the detailed
            level, you cannot supply a function here.

            This replaces the need to define
            store_incorrect_attempts_function and
            pull_incorrect_attempts_function.

            Only necessary if the save_pull_function was not defined
            in the class instantiation. But if defined here, it will
            override the class instantiation.

            The current pre-defined function types are:
                'bigquery': Pulls and stores the incorrect attempts from a
                    BigQuery table.
        :param all_incorrect_attempts_args: If
            all_incorrect_attempts_function is defined, you can supply the
            arguments for the type of function here. For example, if using
            'bigquery', you would supply:

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
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, email_col and datetime_col must be
            defined here.
        :param store_incorrect_attempts_function: The function to store
            the datetime and username when an incorrect login attempt
            occurs. This can be a callable function or a string. At a
            minimum, a callable function should take 'email' as an
            argument, but can include other arguments as well. The
            function should pull in store_incorrect_attempts_args, which
            can be used for things like accessing and storing to a
            database. A callable function can return an error message as a
            string, which our error handler will handle.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b)
            all_incorrect_attempts_function was not defind in this method.
            But if defined here, it will override either of those.

            The current pre-defined function types are:
                'bigquery': Stores the attempted datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with two columns corresponding to email and
                    datetime (see store_incorrect_attempts_args below for
                    how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. This should not include
            'email' since that will automatically be added here.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc.

            Only necessary if store_incorrect_attempts_function is defined
            when you call this method.

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
            email_col (str): The name of the column in the BigQuery
                table that contains the emails.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, email_col and datetime_col must be
            defined here.
        :param pull_incorrect_attempts_function: The function to pull the
            datetimes associated with a username for incorrect login
            attempts. This can be a callable function or a string.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b)
            all_incorrect_attempts_function was not defind in this method.
            But if defined here, it will override either of those.

            The function should pull in pull_incorrect_attempts_args,
            which can be used for things like accessing and pulling from a
            database. At a minimum, a callable function should take
            'email' as one of the pull_incorrect_attempts_args, but can
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
                    with two columns corresponding to email and
                    datetime (see pull_incorrect_attempts_args below for
                    how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. This should not include
            'email' since that will automatically be added here.
            Instead, it should include things like database name, table
            name, credentials to log into the database, etc.

            Only necessary if pull_incorrect_attempts_function is defined
            when you call this method.

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
            email_col (str): The name of the column in the BigQuery
                table that contains the emails.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, email_col and datetime_col must be
            defined here.
        """
        # check on whether all session state inputs exist and are the
        # correct type and whether the inputs are within the correct set
        # of options
        if not self._check_form_inputs(location, 'register_user'):
            return False

        # set the email variables
        if verify_email is True:
            check_inputs = True
        else:
            check_inputs = False
        email_function, email_inputs, email_creds = self._define_email_vars(
            'register_user', email_function, email_inputs, email_creds,
            check_inputs=check_inputs)
        # this will return false for email_function if there was an error
        if not email_function:
            return False
        # set the credential saving variables
        cred_save_function, cred_save_args = self._define_save_pull_vars(
            'register_user', 'cred_save_args',
            cred_save_function, cred_save_args)
        # this will return false for cred_save_function if there was an
        # error
        if not cred_save_function:
            return False

        if preauthorization:
            # choose the correct save & pull functions & arguments, as
            # well as the correct incorrect attempts functions and args
            funcs_args_defined, funcs_and_args = (
                self._define_register_user_functions_args(
                    auth_code_pull_function, auth_code_pull_args,
                    all_locked_function, all_locked_args,
                    locked_info_function, locked_info_args,
                    store_locked_time_function, store_locked_time_args,
                    all_incorrect_attempts_function, all_incorrect_attempts_args,
                    store_incorrect_attempts_function,
                    store_incorrect_attempts_args,
                    pull_incorrect_attempts_function,
                    pull_incorrect_attempts_args))
            if not funcs_args_defined:
                return False
            else:
                (auth_code_pull_function, auth_code_pull_args,
                 locked_info_function, locked_info_args,
                 store_locked_time_function, store_locked_time_args,
                 store_incorrect_attempts_function,
                 store_incorrect_attempts_args,
                 pull_incorrect_attempts_function,
                 pull_incorrect_attempts_args) = funcs_and_args
            if not self._check_register_user_storage_functions(
                    locked_info_function, store_locked_time_function,
                    store_incorrect_attempts_function,
                    pull_incorrect_attempts_function):
                return False

        if location == 'main':
            register_user_form = st.form('Register user')
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user')

        register_user_form.subheader('Register user')
        # we need keys for all of these so they can be accessed in the
        # callback through session_state (such as
        # st.session_state['register_user_email'])
        new_email = register_user_form.text_input(
            'Email', key=email_text_key).lower()
        new_username = register_user_form.text_input(
            'Username', key=username_text_key).lower()
        new_password = register_user_form.text_input(
            'Password', type='password', key=password_text_key)
        new_password_repeat = register_user_form.text_input(
            'Repeat password', type='password',
            key=repeat_password_text_key)
        if preauthorization:
            auth_code = register_user_form.text_input(
                'Authorization code', type='password',
                key=auth_code_key)

        register_user_form.form_submit_button(
            'Register', on_click=self._check_and_register_user,
            args=(email_text_key, username_text_key, password_text_key,
                  repeat_password_text_key, auth_code_key, preauthorization,
                  verify_email,
                  email_function, email_inputs, email_creds,
                  cred_save_function, cred_save_args,
                  auth_code_pull_function, auth_code_pull_args,
                  incorrect_attempts, locked_hours,
                  locked_info_function, locked_info_args,
                  store_locked_time_function, store_locked_time_args,
                  store_incorrect_attempts_function,
                  store_incorrect_attempts_args,
                  pull_incorrect_attempts_function,
                  pull_incorrect_attempts_args))

    def check_authentication_status(self) -> bool:
        """Check if the user is authenticated."""
        if ('stauth' in st.session_state and 'authentication_status' in
                st.session_state.stauth and st.session_state.stauth[
                'authentication_status']):
            return True
        else:
            return False

    def _define_login_functions_args(
            self,
            password_pull_function: Union[str, Callable],
            check_email_verification: bool,
            password_pull_args: dict,
            all_locked_function: str,
            all_locked_args: dict,
            locked_info_function: Union[str, Callable],
            locked_info_args: dict,
            store_locked_time_function: Union[str, Callable],
            store_locked_time_args: dict,
            store_unlocked_time_function: Union[str, Callable],
            store_unlocked_time_args: dict,
            all_incorrect_attempts_function: str,
            all_incorrect_attempts_args: dict,
            store_incorrect_attempts_function: Union[str, Callable],
            store_incorrect_attempts_args: dict,
            pull_incorrect_attempts_function: Union[str, Callable],
            pull_incorrect_attempts_args: dict
    ) -> Tuple[bool, Union[tuple, None]]:
        """
        Define the functions and arguments that are needed for the
            login method. Uses a hierarchy method, where the highest level
            allows you to define the least, but if you define a lower
            level that will override any higher levels.

        Hierarchy:
        1. Class definition (self.save_pull_function, self.save_pull_args)
            a. General method definition (all_locked_function,
                                          all_locked_args)
                i. Specific method def. (locked_info_function,
                                         locked_info_args)
                ii. Specific method def. (store_locked_time_function,
                                          store_locked_time_args)
                iii. Specific method def. (store_unlocked_time_function,
                                           store_unlocked_time_args)
            b. General method definition (all_incorrect_attempts_function,
                                          all_incorrect_attempts_args)
                i. Specific method def. (store_incorrect_attempts_function,
                                         store_incorrect_attempts_args)
                ii. Specific method def. (pull_incorrect_attempts_function,
                                          pull_incorrect_attempts_args)
            c. General/specific method def. (password_pull_function,
                                             password_pull_args)
        """
        # if checking email verification, we want the set of args to check
        # against to also include the email_verification_col
        if check_email_verification and password_pull_function == 'bigquery':
            self.save_pull_args_function_specific['bigquery']['login'][
                'password_pull_args'].extend(['email_verification_col'])
        password_pull_function, password_pull_args = self._define_save_pull_vars(
            'login', 'password_pull_args',
            password_pull_function, password_pull_args)
        # this will return false for all_locked_function if there was an
        # error
        if not password_pull_function:
            return False, None

        all_locked_function, all_locked_args = self._define_save_pull_vars(
            'login', 'all_locked_args',
            all_locked_function, all_locked_args, check_args=False)
        if all_locked_function is not None and not all_locked_function:
            return False, None
        locked_info_function, locked_info_args = self._define_save_pull_vars(
            'login', 'locked_info_args',
            locked_info_function, locked_info_args,
            all_locked_function, all_locked_args)
        if locked_info_function is not None and not locked_info_function:
            return False, None
        store_locked_time_function, store_locked_time_args = (
            self._define_save_pull_vars(
                'login', 'store_locked_time_args',
                store_locked_time_function, store_locked_time_args,
                all_locked_function, all_locked_args))
        if (store_locked_time_function is not None and
                not store_locked_time_function):
            return False, None
        store_unlocked_time_function, store_unlocked_time_args = (
            self._define_save_pull_vars(
                'login', 'store_unlocked_time_args',
                store_unlocked_time_function, store_unlocked_time_args,
                all_locked_function, all_locked_args))
        if (store_unlocked_time_function is not None and
                not store_unlocked_time_function):
            return False, None

        all_incorrect_attempts_function, all_incorrect_attempts_args = (
            self._define_save_pull_vars(
                'login', 'all_incorrect_attempts_args',
                all_incorrect_attempts_function, all_incorrect_attempts_args,
                check_args=False))
        if (all_incorrect_attempts_function is not None and
                not all_incorrect_attempts_function):
            return False, None
        store_incorrect_attempts_function, store_incorrect_attempts_args = (
            self._define_save_pull_vars(
            'login', 'store_incorrect_attempts_args',
                store_incorrect_attempts_function,
                store_incorrect_attempts_args,
                all_incorrect_attempts_function, all_incorrect_attempts_args))
        if (store_incorrect_attempts_function is not None and
                not store_incorrect_attempts_function):
            return False, None
        pull_incorrect_attempts_function, pull_incorrect_attempts_args = (
            self._define_save_pull_vars(
            'login', 'pull_incorrect_attempts_args',
                pull_incorrect_attempts_function, pull_incorrect_attempts_args,
                all_incorrect_attempts_function, all_incorrect_attempts_args))
        if (pull_incorrect_attempts_function is not None and
                not pull_incorrect_attempts_function):
            return False, None

        return (True,
                (password_pull_function, password_pull_args,
                 locked_info_function, locked_info_args,
                 store_locked_time_function, store_locked_time_args,
                 store_unlocked_time_function, store_unlocked_time_args,
                 store_incorrect_attempts_function,
                 store_incorrect_attempts_args,
                 pull_incorrect_attempts_function,
                 pull_incorrect_attempts_args))

    def _check_login_storage_functions(
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

    def _rename_password_pull_args(self, password_pull_args: dict) -> dict:
        """Update the target and reference columns and reference value."""
        password_pull_args['reference_col'] = password_pull_args[
            'username_col']
        password_pull_args['reference_value'] = password_pull_args[
            'username']
        if 'email_verification_col' in password_pull_args:
            password_pull_args['target_col'] = [password_pull_args[
                'password_col'], password_pull_args[
                'email_verification_col']]
        else:
            password_pull_args['target_col'] = password_pull_args[
                'password_col']
        del password_pull_args['username_col']
        del password_pull_args['username']
        del password_pull_args['password_col']
        if 'email_verification_col' in password_pull_args:
            del password_pull_args['email_verification_col']
        return password_pull_args

    def _pull_login_locked_unlocked_error_handler(self, indicator: str,
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

    def _pull_login_locked_unlocked_info(
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
                indicator, value = db.pull_login_locked_info_bigquery(
                    **locked_info_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The locked_info_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = locked_info_function(**locked_info_args)
        if self._pull_login_locked_unlocked_error_handler(indicator, value):
            return True, value
        return False, None

    def _is_account_locked(self,
                           latest_lock: datetime,
                           latest_unlock: datetime,
                           locked_hours: int,
                           form: str) -> bool:
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
        # we are locked if the times both exist and the latest lock is
        # more recent, or if the latest lock exists and the latest unlock
        # does not
        if ((latest_lock is not None and latest_unlock is not None
                and latest_lock > latest_unlock and latest_lock > locked_time)
                or
                (latest_lock is not None and latest_unlock is None
                 and latest_lock > locked_time)):
            eh.add_user_error(
                form,
                "Your account is locked. Please try again later.")
            return True
        return False

    def _check_locked_account_login(
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
        # if we have a locked_info_function, check that;
        # otherwise just use what we have saved in the session_state
        if locked_info_function is not None:
            # pull the latest locked and unlocked times
            pull_worked, values = self._pull_login_locked_unlocked_info(
                username, locked_info_function, locked_info_args)
            if pull_worked:
                latest_lock, latest_unlock = values
            else:
                return True
        else:
            if ('login_lock' in st.session_state.stauth and
                    username in st.session_state.stauth['login_lock'].keys()):
                latest_lock = max(st.session_state.stauth['login_lock'][
                                      username])
            else:
                latest_lock = None
            if ('login_unlock' in st.session_state.stauth and
                    username in st.session_state.stauth[
                        'login_unlock'].keys()):
                latest_unlock = max(st.session_state.stauth['login_unlock'][
                                        username])
            else:
                latest_unlock = None
        return self._is_account_locked(
            latest_lock, latest_unlock, locked_hours, 'login')

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
                "Error: " + str(verified[1]))
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
            check_email_verification: bool,
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
        :param check_email_verification: Whether to check if the user's
            email has been verified. This will happen within the same
            function as the password_pull_function, so you will need to
            incorporate any necessary arguments into password_pull_args.
            If writing your own function for password_pull_function, you
            should make sure to check the email verification if this is
            set to True.
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
            email_verification_col (str): Only necessary if the
                check_email_verification is set to True. The name of the
                column in the BigQuery table that contains the email
                verification status (True or False). The built-in
                BigQuery version assumes the email verification column is
                in the same table as the password. If not, you will need
                to build your own function to pull from separate places.
        """
        # add the username to the arguments for the password pull function
        password_pull_args = self._add_username_to_args(
            username, password_pull_args)
        # pull the password
        if isinstance(password_pull_function, str):
            if password_pull_function.lower() == 'bigquery':
                password_pull_args = self._rename_password_pull_args(
                    password_pull_args)
                db = BQTools()
                indicator, value = db.pull_value_based_on_other_col_value(
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
            if check_email_verification:
                pulled_password = value[0]
                email_verified = value[1]
                if not email_verified:
                    eh.add_user_error(
                        'login',
                        "Your email has not been verified. Please check "
                        "your email for the verification link.")
                    return False
            else:
                pulled_password = value
            verified = Hasher([password]).check([pulled_password])[0]
            st.write("verified", verified)
            # we can have errors here if the password doesn't match or
            # there is an issue running the check
            return self._password_verification_error_handler(verified)
        return False

    def _store_lock_unlock_time_login(
            self,
            username: str,
            store_function: Union[str, Callable],
            store_args: dict,
            lock_or_unlock: str) -> Union[None, str]:
        """
        Store the locked or unlocked time associated with the username.

        :param username: The username to store the lock or unlock time
            for.
        :param store_function: The function to store the lock or
            unlocked datetime associated with the username. This can be a
            callable function or a string.

            The function should pull in store_args, which can be used for
            things like accessing and storing to a database. At a minimum,
            a callable function should take 'username' as one of the
            store_args, but can include other arguments as well. A
            callable function can return an error message as a string,
            which our error handler will handle.

            The current pre-defined function types are:
                'bigquery': Stores the unlocked or locked datetime to a
                    BigQuery table. This pre-defined version will look for
                    a table with three columns corresponding to username,
                    locked_time and unlocked_time (see store_args below
                    for how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_args: Arguments for the store_function. This should
            not include 'username' since that will automatically be added
            here. Instead, it should include things like database name,
            table name, credentials to log into the database, etc.

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
            username_col (str): The name of the column in the
                BigQuery table that contains the usernames.
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
            eh.add_dev_error(
                'login',
                "There was an error saving the unlock time. "
                "Error: " + error)

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
            st.session_state.stauth['login_unlock'] = {}
        if username not in st.session_state.stauth['login_unlock'].keys():
            st.session_state.stauth['login_unlock'][username] = []
        # append the current datetime
        st.session_state.stauth['login_unlock'][username].append(
            datetime.utcnow())

        if store_unlocked_time_function is not None:
            error = self._store_lock_unlock_time_login(
                username, store_unlocked_time_function,
                store_unlocked_time_args, 'unlock')
            self._unlock_time_save_error_handler(error)

    def _lock_time_save_error_handler(self, error: str,
                                      form: str) -> None:
        """
        Records any errors from the lock time saving process.
        """
        if error is not None:
            eh.add_dev_error(
                form,
                "There was an error saving the lock time. "
                "Error: " + error)

    def _store_login_lock_time_handler(
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
        if 'login_lock' not in st.session_state.stauth:
            st.session_state.stauth['login_lock'] = {}
        if username not in st.session_state.stauth['login_lock'].keys():
            st.session_state.stauth['login_lock'][username] = []
        # append the current datetime
        st.session_state.stauth['login_lock'][username].append(
            datetime.utcnow())

        if store_locked_time_function is not None:
            error = self._store_lock_unlock_time_login(
                username, store_locked_time_function, store_locked_time_args,
                'lock')
            self._lock_time_save_error_handler(error, 'login')

    def _add_username_or_email_to_args(
            self, username_or_email: str, existing_args: dict) -> dict:
        """Add the username or email to existing_args."""
        if existing_args is None:
            existing_args = {}
        existing_args['username_or_email'] = username_or_email
        return existing_args

    def _rename_incorrect_attempt_args(
            self, incorrect_attempts_args: dict,
            auth_type: str) -> dict:
        """Update the target and reference columns and reference value."""
        if auth_type == 'login':
            incorrect_attempts_args['username_or_email_col'] = (
                incorrect_attempts_args['username_col'])
            del incorrect_attempts_args['username_col']
        else:
            incorrect_attempts_args['username_or_email_col'] = (
                incorrect_attempts_args['email_col'])
            del incorrect_attempts_args['email_col']
        return incorrect_attempts_args

    def _store_incorrect_attempt(
            self,
            username_or_email: str,
            store_incorrect_attempts_function: Union[str, Callable],
            store_incorrect_attempts_args: dict,
            auth_type: str = None) -> Union[None, str]:
        """
        Store the datetime associated with the username or email for an
        incorrect authorization (either login or registering with an
        authorization code) attempt.

        :param username_or_email: The username or email to store the lock
            time for.
        :param store_incorrect_attempts_function: The function to store
            the datetime and username or email when an incorrect
            authorization attempt occurs. This can be a callable function
            or a string. At a minimum, a callable function should take
            'username_or_email' as an argument, but can include other
            arguments as well. The function should pull in
            store_incorrect_attempts_args, which can be used for things
            like accessing and storing to a database. A callable function
            can return an error message as a string, which our error
            handler will handle.

            The current pre-defined function types are:
                'bigquery': Stores the attempted datetime to a BigQuery
                    table. This pre-defined version will look for a table
                    with two columns corresponding to username or email
                    and datetime (see store_incorrect_attempts_args below
                    for how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param store_incorrect_attempts_args: Arguments for the
            store_incorrect_attempts_function. This should not include
            'username_or_email' since that will automatically be added
            here. Instead, it should include things like database name,
            table name, credentials to log into the database, etc.

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
            username_col (str): The name of the column in the
                BigQuery table that contains the usernames.
            OR
            email_col (str): The name of the column in the BigQuery
                table that contains the emails. The code will pull the
                correct version (username_col or email_col) depending on
                the auth_type variable.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.
        :param auth_type: The type of authentication that the incorrect
            attempt is associated with. This can be 'login' or
            'register_user'. Only required if
            store_incorrect_attempts_function is 'bigquery'.

        :return error: The error message if there is an error, otherwise
            None.
        """
        store_incorrect_attempts_args = self._add_username_or_email_to_args(
            username_or_email, store_incorrect_attempts_args)
        if isinstance(store_incorrect_attempts_function, str):
            if store_incorrect_attempts_function.lower() == 'bigquery':
                # change the column names to match the bigquery table
                store_incorrect_attempts_args = (
                    self._rename_incorrect_attempt_args(
                        store_incorrect_attempts_args, auth_type))
                db = BQTools()
                error = db.store_incorrect_auth_times(
                    **store_incorrect_attempts_args)
            else:
                error = ("The store_incorrect_attempts_function method is not "
                         "recognized. The available options are: 'bigquery' "
                         "or a callable function.")
        else:
            error = store_incorrect_attempts_function(
                **store_incorrect_attempts_args)
        return error

    def _incorrect_attempts_error_handler(self, error: str,
                                          form: str) -> None:
        """
        Records any errors from the incorrect attempt saving process.
        """
        if error is not None:
            eh.add_dev_error(
                form,
                "There was an error saving the incorrect attempt time. "
                "Error: " + error)
            return False
        return True

    def _store_incorrect_login_attempts_handler(
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
            st.session_state.stauth['failed_login_attempts'] = {}
        if username not in st.session_state.stauth[
                'failed_login_attempts'].keys():
            st.session_state.stauth['failed_login_attempts'][username] = []
        # append the current datetime
        st.session_state.stauth['failed_login_attempts'][username].append(
            datetime.utcnow())

        if store_incorrect_attempts_function is not None:
            error = self._store_incorrect_attempt(
                username, store_incorrect_attempts_function,
                store_incorrect_attempts_args, 'login')
            return self._incorrect_attempts_error_handler(error, 'login')
        else:
            return True

    def _incorrect_attempts_pull_error_handler(
            self, indicator: str, value: str, form: str) -> bool:
        """ Records any errors from the incorrect attempts pulling
            process."""
        if indicator == 'dev_error':
            eh.add_dev_error(
                form,
                "There was an error pulling incorrect attempts. "
                "Error: " + value)
            return False
        return True

    def _pull_incorrect_attempts(
            self,
            username_or_email: str,
            auth_type: str,
            pull_incorrect_attempts_function: Union[str, Callable] = None,
            pull_incorrect_attempts_args: dict = None) -> (
            Tuple[bool, Union[pd.Series, None]]):
        """
        Pull incorrect authorization (either login or registering with an
        authorization code) attempts for a given username or email.

        :param username: The username or email to check.
        :param pull_incorrect_attempts_function: The function to pull the
            datetimes associated with a username or email for incorrect
            authorization attempts. This can be a callable function or a
            string.

            The function should pull in pull_incorrect_attempts_args,
            which can be used for things like accessing and pulling from a
            database. At a minimum, a callable function should take
            'username_or_email' as one of the
            pull_incorrect_attempts_args, but can include other arguments
            as well.
            A callable function should return:
            - A tuple of an indicator and a value
            - The indicator should be either 'dev_error' or 'success'.
            - The value should be a string that contains the error
                message when the indicator is 'dev_error' and a
                pandas series of datetimes (if data exists) or None (if
                data does not exist) when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the incorrect authorization datetimes
                    from a BigQuery table.
                    This pre-defined version will look for a table
                    with two columns corresponding to username or email
                    and datetime (see pull_incorrect_attempts_args below
                    for how to define there).
                    Note that if using 'bigquery' here, in our other
                    database functions, you should also be using the
                    'bigquery' option or using your own method that pulls
                    from a table set up in the same way.
        :param pull_incorrect_attempts_args: Arguments for the
            pull_incorrect_attempts_function. This should not include
            'username_or_email' since that will automatically be added
            here. Instead, it should include things like database name,
            table name, credentials to log into the database, etc.

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
            username_col (str): The name of the column in the
                BigQuery table that contains the usernames.
            OR
            email_col (str): The name of the column in the BigQuery
                table that contains the emails. The code will pull the
                correct version (username_col or email_col) depending on
                the auth_type variable.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime.
        :param auth_type: The type of authentication that the incorrect
            attempt is associated with. This can be 'login' or
            'register_user'. Only required if
            store_incorrect_attempts_function is 'bigquery'

        :return: Tuple with the first value of True if the pull worked and
            False if there were errors with the pull. The second value
            should be either a pandas Series if the pull worked and there
            is existing data or None if the pull "worked" but no data yet
            exists in the database. The second value will be None if there
            was an error.
        """
        # add the username or email to the arguments
        pull_incorrect_attempts_args = self._add_username_or_email_to_args(
            username_or_email, pull_incorrect_attempts_args)
        if isinstance(pull_incorrect_attempts_function, str):
            if pull_incorrect_attempts_function.lower() == 'bigquery':
                # change the column names to match the bigquery table
                pull_incorrect_attempts_args = (
                    self._rename_incorrect_attempt_args(
                        pull_incorrect_attempts_args, auth_type))
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

        if self._incorrect_attempts_pull_error_handler(indicator, value,
                                                       auth_type):
            return True, value
        return False, None

    def _check_too_many_login_attempts(
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
                username, 'login', pull_incorrect_attempts_function,
                pull_incorrect_attempts_args)
            locks_pull_worked, lock_unlock = (
                self._pull_login_locked_unlocked_info(
                    username, locked_info_function, locked_info_args))
            _, latest_unlock = lock_unlock
        else:
            # if not, just use the session_state
            if ('failed_login_attempts' in st.session_state.stauth and
                    username in st.session_state.stauth[
                        'failed_login_attempts'].keys()):
                attempts = pd.Series(st.session_state.stauth[
                                         'failed_login_attempts'][username])
            else:
                attempts = None
            if ('login_unlock' in st.session_state.stauth and
                    username in st.session_state.stauth[
                        'login_unlock'].keys()):
                latest_unlock = max(st.session_state.stauth['login_unlock'][
                    username])
            else:
                latest_unlock = None
            attempts_pull_worked = True
            locks_pull_worked = True

        if attempts_pull_worked and locks_pull_worked and attempts is not None:
            # sort attempts by datetime, starting with the most recent
            attempts = attempts.sort_values(ascending=False)
            # count the number of attempts in the last locked_hours
            recent_attempts = attempts[
                attempts > datetime.utcnow() - timedelta(hours=locked_hours)]
            # count the number of attempts after latest_unlock
            if latest_unlock is not None:
                recent_attempts = recent_attempts[
                    recent_attempts > latest_unlock]
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
            check_email_verification: bool = False,
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
        :param check_email_verification: Whether to check if the email
            associated with the username has been verified. See the
            docstring for login for more information.
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
            # first see if the account should be locked
            if self._check_locked_account_login(username, locked_info_function,
                                                locked_info_args, locked_hours):
                st.session_state.stauth['username'] = None
                st.session_state.stauth['authentication_status'] = False
            else:
                # only continue if the password is correct (and the email
                # has been verified, if requiring that)
                if self._check_pw(password, username, password_pull_function,
                                  check_email_verification,
                                  password_pull_args):
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
                    st.session_state.stauth['username'] = None
                    st.session_state.stauth['authentication_status'] = False
                    if (not self._store_incorrect_login_attempts_handler(
                            username, store_incorrect_attempts_function,
                            store_incorrect_attempts_args)
                            or
                            self._check_too_many_login_attempts(
                                username, pull_incorrect_attempts_function,
                                pull_incorrect_attempts_args,
                                locked_info_function, locked_info_args,
                                locked_hours, incorrect_attempts)):
                        self._store_login_lock_time_handler(
                            username, store_locked_time_function,
                            store_locked_time_args)
        else:
            # here we have already set any errors in previous functions,
            # so just set authentication_status to false
            st.session_state.stauth['username'] = None
            st.session_state.stauth['authentication_status'] = False

    def login(self,
              location: str = 'main',
              username_text_key: str = 'login_username',
              password_text_key: str = 'login_password',
              password_pull_function: Union[str, Callable] = 'bigquery',
              check_email_verification: bool = False,
              password_pull_args: dict = None,
              incorrect_attempts: int = 10,
              locked_hours: int = 24,
              all_locked_function: str = None,
              all_locked_args: dict = None,
              locked_info_function: Union[str, Callable] = None,
              locked_info_args: dict = None,
              store_locked_time_function: Union[str, Callable] = None,
              store_locked_time_args: dict = None,
              store_unlocked_time_function: Union[str, Callable] = None,
              store_unlocked_time_args: dict = None,
              all_incorrect_attempts_function: str = None,
              all_incorrect_attempts_args: dict = None,
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

            Only necessary if the save_pull_function was not defined
            in the class instantiation. But if defined here, it will
            override the class instantiation.

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
        :param check_email_verification: Whether to check if the user's
            email has been verified. This will happen within the same
            function as the password_pull_function, so you will need to
            incorporate any necessary arguments into password_pull_args.
            If writing your own function for password_pull_function, you
            should make sure to check the email verification if this is
            set to True.
        :param password_pull_args: Arguments for the
            password_pull_function.

            Only necessary if password_pull_function is defined when you
            call this method.

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
            email_verification_col (str): Only necessary if the
                check_email_verification is set to True. The name of the
                column in the BigQuery table that contains the email
                verification status (True or False). The built-in
                BigQuery version assumes the email verification column is
                in the same table as the password. If not, you will need
                to build your own function to pull from separate places.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, username_col and password_col must be
            defined here.
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

        :param all_locked_function: Since all the lock-type functions
            below behave similarly, you can define all of them at once
            here if the input is a string. For example, you could say
            all_locked_function='bigquery'. However, since each function
            behaves somewhat differently at the detailed level, you cannot
            supply a function here.

            This replaces the need to define locked_info_function,
            store_locked_time_function and store_unlocked_time_function.

            Only necessary if the save_pull_function was not defined
            in the class instantiation. But if defined here, it will
            override the class instantiation.

            The current pre-defined function types are:
                'bigquery': Pulls ans stores the locked and unlocked
                datetimes from a BigQuery table.
        :param all_locked_args: If all_locked_function is defined, you
            can supply the arguments for the type of function here. For
            example, if using 'bigquery', you would supply:

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

            Only necessary if all_locked_function is defined when you
            call this method.

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, username_col, locked_time_col and
            unlocked_time_col must be defined here.
        :param locked_info_function: The function to pull the locked
            information associated with the username. This can be a
            callable function or a string.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b) all_locked_function
            was not defind in this method. But if defined here, it will
            override either of those.

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

            Only necessary if locked_info_function is defined when you
            call this method.

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

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, username_col, locked_time_col and
            unlocked_time_col must be defined here.
        :param store_locked_time_function: The function to store the
            locked datetime associated with the username. This can be a
            callable function or a string.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b) all_locked_function
            was not defind in this method. But if defined here, it will
            override either of those.

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

            Only necessary if store_locked_time_function is defined when
            you call this method.

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

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, username_col, locked_time_col and
            unlocked_time_col must be defined here.
        :param store_unlocked_time_function: The function to store the
            unlocked times associated with the username. See
            store_locked_time_function above - this just stores the unlock
            time instead of the lock time.
        :param store_unlocked_time_args: Arguments for the
            store_unlocked_times_function. See
            store_locked_time_args above - these variable will be the same
            here.
        :param all_incorrect_attempts_function: Since all the
            incorrect attempts-type functions below behave similarly,
            you can define all of them at once here if the input is a
            string. For example, you could say
            all_incorrect_attempts_function='bigquery'. However, since
            each function behaves somewhat differently at the detailed
            level, you cannot supply a function here.

            This replaces the need to define
            store_incorrect_attempts_function and
            pull_incorrect_attempts_function.

            Only necessary if the save_pull_function was not defined
            in the class instantiation. But if defined here, it will
            override the class instantiation.

            The current pre-defined function types are:
                'bigquery': Pulls and stores the incorrect attempts from a
                    BigQuery table.
        :param all_incorrect_attempts_args: If
            all_incorrect_attempts_function is defined, you can supply the
            arguments for the type of function here. For example, if using
            'bigquery', you would supply:

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

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, username_col and datetime_col must be
            defined here.
        :param store_incorrect_attempts_function: The function to store
            the datetime and username when an incorrect login attempt
            occurs. This can be a callable function or a string. At a
            minimum, a callable function should take 'username' as an
            argument, but can include other arguments as well. The
            function should pull in store_incorrect_attempts_args, which
            can be used for things like accessing and storing to a
            database. A callable function can return an error message as a
            string, which our error handler will handle.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b)
            all_incorrect_attempts_function was not defind in this method.
            But if defined here, it will override either of those.

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

            Only necessary if store_incorrect_attempts_function is defined
            when you call this method.

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

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, username_col and datetime_col must be
            defined here.
        :param pull_incorrect_attempts_function: The function to pull the
            datetimes associated with a username for incorrect login
            attempts. This can be a callable function or a string.

            Only necessary if both a) the save_pull_function was not
            defined in the class instantiation and b)
            all_incorrect_attempts_function was not defind in this method.
            But if defined here, it will override either of those.

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

            Only necessary if pull_incorrect_attempts_function is defined
            when you call this method.

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

            Note that bq_creds, project and dataset could be defined in
            the class instantiation, although they can be overwritten
            here. table_name, username_col and datetime_col must be
            defined here.
        """
        # choose the correct save & pull functions & arguments, as well
        # as the correct incorrect attempts functions and arguments
        funcs_args_defined, funcs_and_args = (
            self._define_login_functions_args(
                password_pull_function, check_email_verification,
                password_pull_args,
                all_locked_function, all_locked_args,
                locked_info_function, locked_info_args,
                store_locked_time_function, store_locked_time_args,
                store_unlocked_time_function, store_unlocked_time_args,
                all_incorrect_attempts_function, all_incorrect_attempts_args,
                store_incorrect_attempts_function,
                store_incorrect_attempts_args,
                pull_incorrect_attempts_function,
                pull_incorrect_attempts_args))
        if not funcs_args_defined:
            return False
        else:
            (password_pull_function, password_pull_args,
             locked_info_function, locked_info_args,
             store_locked_time_function, store_locked_time_args,
             store_unlocked_time_function, store_unlocked_time_args,
             store_incorrect_attempts_function,
             store_incorrect_attempts_args,
             pull_incorrect_attempts_function,
             pull_incorrect_attempts_args) = funcs_and_args

        # check whether the inputs are within the correct set of options
        if not self._check_form_inputs(location, 'login') or \
                not self._check_login_storage_functions(
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
                  password_pull_function, check_email_verification,
                  password_pull_args,
                  incorrect_attempts, locked_hours,
                  locked_info_function, locked_info_args,
                  store_locked_time_function, store_locked_time_args,
                  store_unlocked_time_function, store_unlocked_time_args,
                  store_incorrect_attempts_function,
                  store_incorrect_attempts_args,
                  pull_incorrect_attempts_function,
                  pull_incorrect_attempts_args))

    def _logout(self) -> None:
        """Remove the session states showing the user is logged in."""
        st.session_state.stauth['username'] = None
        st.session_state.stauth['authentication_status'] = False

    def logout(self,
               location: str = 'main',
               logout_button_key: str = 'logout_button') -> None:
        """
        Creates a logout button.

        :param location: The location of the login form i.e. main or
            sidebar.
        :param logout_button_key: The key for the logout button. We
            attempt to default to a unique key, but you can put your own
            in here if you want to customize it or have clashes with other
            keys.
        """
        # check whether the inputs are within the correct set of options
        if not self._check_form_inputs(location, 'logout'):
            return False

        if location == 'main':
            st.button('Logout', key=logout_button_key, on_click=self._logout)
        elif location == 'sidebar':
            st.sidebar.button('Logout', key=logout_button_key,
                              on_click=self._logout)

    def _check_email_info(self, email: str) -> bool:
        """Check whether the email is filled in."""
        if not (len(email) > 0):
            eh.add_user_error(
                'forgot_username',
                "Please enter an email.")
            return False
        return True

    def _add_email_to_args(
            self, email: str, existing_args: dict) -> dict:
        """Add the email to existing_args."""
        if existing_args is None:
            existing_args = {}
        existing_args['email'] = email
        return existing_args

    def _rename_username_pull_args(self, username_pull_args: dict) -> dict:
        """Update the target and reference columns and reference value."""
        username_pull_args['reference_col'] = username_pull_args['email_col']
        username_pull_args['reference_value'] = username_pull_args['email']
        username_pull_args['target_col'] = username_pull_args['username_col']
        del username_pull_args['email_col']
        del username_pull_args['email']
        del username_pull_args['username_col']
        return username_pull_args

    def _username_pull_error_handler(self, pull_type: str, indicator: str,
                                     value: str) -> bool:
        """ Records any errors from the username pulling process. Note
            that since we don't want the user to know if they entered a
            non-valid email, we only record dev_errors here."""
        if indicator == 'dev_error':
            eh.add_dev_error(
                pull_type,
                "There was an error pulling the user's username. "
                "Error: " + value)
            return False
        elif indicator == 'user_error':
            # at this point, the pull worked but no users matched, so
            # clear any errors
            eh.clear_errors()
            return False
        return True

    def _pull_username(
            self,
            email: str,
            pull_type: str,
            username_pull_function: Union[str, Callable],
            username_pull_args: dict = None) -> Union[bool, str]:
        """
        Pulls the username associated with the email.

        :param email: The entered email.
        :param pull_type: The type of pull function we are using, either
            'forgot_username' or 'forgot_password'. This is used when
            defining the type of errors we get.
        :param username_pull_function: The function to pull the
            username associated with the email. This can be a callable
            function or a string.

            At a minimum, a callable function should take 'email' as
            an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error' or
                'success'
             - The value should be a string that contains the error
                message when the indicator is 'dev_error' and the username
                when the indicator is 'success'. The value associated with
                'user_error' isn't used as that is the case when the
                username does not exist in the system and we don't tell
                the user that.

            The current pre-defined function types are:
                'bigquery': Pulls the username from a BigQuery table.
        :param username_pull_args: Arguments for the
            username_pull_function. This should not include 'email'
            since that will automatically be added here based on the
            user's input.

            If using 'bigquery' as your username_pull_function, the
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
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
        """
        # add the email to the arguments for the username pull function
        username_pull_args = self._add_email_to_args(
            email, username_pull_args)
        # pull the username
        if isinstance(username_pull_function, str):
            if username_pull_function.lower() == 'bigquery':
                username_pull_args = self._rename_username_pull_args(
                    username_pull_args)
                db = BQTools()
                indicator, value = db.pull_value_based_on_other_col_value(
                    **username_pull_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The username_pull_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = username_pull_function(**username_pull_args)

        # only continue if we didn't have any issues getting the username
        if self._username_pull_error_handler(pull_type, indicator, value):
            return value
        return False

    def _get_username(
            self,
            email_text_key: str,
            username_pull_function: Union[str, Callable],
            username_pull_args: dict = None,
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None) -> None:
        """
        Checks the validity of the entered email and, if correct,
        send the user the associated username.

        :param email_text_key: The st.session_state name used to access
            the email.
        :param username_pull_function: The function to pull the username
            associated with the email. This can be a callable function
            or a string. See the docstring for forgot_username for more
            information.
        :param username_pull_args: Arguments for the
            username_pull_function. See the docstring for forgot_username
            for more information.
        :param email_function: Provide the method for email here, this can
            be a callable function or a string. See forgot_username for
            more details.
        :param email_inputs: The inputs for the email sending process.
            See forgot_username for more details.
        :param email_creds: The credentials to use for the email API. See
            forgot_username for more details.
        """
        email = st.session_state[email_text_key]

        # make sure the email isn't blank
        if self._check_email_info(email):
            username = self._pull_username(email,
                                           'forgot_username',
                                           username_pull_function,
                                           username_pull_args)
            # username will only be non-False if the username was pulled
            if username and email_function is not None:
                self._send_user_email(
                    'forgot_username', email_inputs, email,
                    email_function, email_creds, username)

    def forgot_username(
            self,
            location: str = 'main',
            email_text_key: str = 'forgot_username_email',
            username_pull_function: Union[str, Callable] = None,
            username_pull_args: dict = None,
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None) -> None:
        """
        Creates a forgot username form.

        :param location: The location of the login form i.e. main or
            sidebar.
        :param email_text_key: The key for the email text field. We
            attempt to default to a unique key, but you can put your own
            in here if you want to customize it or have clashes with other
            keys.
        :param username_pull_function: The function to pull the
            username associated with the email. This can be a callable
            function or a string.

            Only necessary if the save_pull_function was not defined
            in the class instantiation. But if defined here, it will
            override the class instantiation.

            At a minimum, a callable function should take 'email' as
            an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error' or
                'success'
             - The value should be a string that contains the error
                message when the indicator is 'dev_error' and the username
                when the indicator is 'success'. The value associated with
                'user_error' isn't used as that is the case when the
                username does not exist in the system and we don't tell
                the user that.

            The current pre-defined function types are:
                'bigquery': Pulls the username from a BigQuery table.
        :param username_pull_args: Arguments for the
            username_pull_function. This should not include 'email'
            since that will automatically be added here based on the
            user's input.

            Only necessary if username_pull_function is defined when you
            call this method.

            If using 'bigquery' as your username_pull_function, the
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
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
        :param email_function:  Provide the method for email here, this
            can be a callable function or a string. The function can also
            return an error message as a string, which will be handled by
            the error handler.

            Only necessary if a) we want to email the user and b)
            email_function was not defined in the class instantiation. If
            we defined the email method in the class instantiation and we
            provide another here, the one here will override the one in
            the class instantiation.

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
        # check whether the inputs are within the correct set of options
        if not self._check_form_inputs(location, 'forgot_username'):
            return False

        # set the email variables
        email_function, email_inputs, email_creds = self._define_email_vars(
            'forgot_username', email_function, email_inputs, email_creds)
        # this will return false for email_function if there was an error
        if not email_function:
            return False
        # set the username pull variables
        username_pull_function, username_pull_args = (
            self._define_save_pull_vars(
                'forgot_username', 'username_pull_args',
                username_pull_function, username_pull_args))
        # this will return false for username_pull_function if there was
        # an error
        if not username_pull_function:
            return False

        if location == 'main':
            forgot_username_form = st.form('Forgot Username')
        else:
            forgot_username_form = st.sidebar.form('Forgot Username')
        forgot_username_form.subheader('Forgot Username')

        # we need a key for email so it can be accessed in the callback
        # through session_state (such as st.session_state[
        # 'forgot_username_email'])
        email = forgot_username_form.text_input(
            'Email', key=email_text_key).lower()
        forgot_username_form.write("If the email exists in our system, "
                                   "we will send you the associated username.")

        forgot_username_form.form_submit_button(
            'Get Username', on_click=self._get_username,
            args=(email_text_key, username_pull_function, username_pull_args,
                  email_function, email_inputs, email_creds))

    def _check_email_username_info(self, email: str, username: str,
                                   repeat_username: str) -> bool:
        """Check whether the email and usernames are filled in, and the
            username matches."""
        if not (len(email) > 0 and len(username) > 0 and
                len(repeat_username) > 0):
            eh.add_user_error(
                'forgot_password',
                "Please enter an email, username and matching username.")
            return False
        if username != repeat_username:
            eh.add_user_error(
                'forgot_password',
                "The usernames do not match. Please try again.")
            return False
        return True

    def _add_inputs_password_update(
            self, password_store_args: dict, username: str,
            password: str) -> dict:
        if password_store_args is None:
            password_store_args = {}
        # add the inputs to password_store_args
        password_store_args['username'] = username
        password_store_args['password'] = password
        return password_store_args

    def _rename_password_store_args(self, password_store_args: dict) -> dict:
        """Update the target and reference columns and reference value."""
        password_store_args['reference_col'] = password_store_args[
            'username_col']
        password_store_args['reference_value'] = password_store_args[
            'username']
        password_store_args['target_col'] = password_store_args['password_col']
        password_store_args['target_value'] = password_store_args['password']
        del password_store_args['username_col']
        del password_store_args['username']
        del password_store_args['password_col']
        del password_store_args['password']
        return password_store_args

    def _update_password(self, password_store_function: Union[Callable, str],
                         password_store_args: dict,
                         username: str, password: str) -> Union[None, str]:
        """Update password for the given username."""
        # first, add the username and password to the args
        password_store_args = self._add_inputs_password_update(
            password_store_args, username, password)
        if isinstance(password_store_function, str):
            if password_store_function.lower() == 'bigquery':
                # update the password_store_args to the correct variable
                # names
                password_store_args = self._rename_password_store_args(
                    password_store_args)
                db = BQTools()
                error = db.update_value_based_on_other_col_value(
                    **password_store_args)
            else:
                error = (
                    "The password_store_function method is not recognized. "
                    "The available options are: 'bigquery' or a "
                    "callable function.")
        else:
            error = password_store_function(**password_store_args)
        return error

    def _password_update_error_handler(self, error: str) -> bool:
        """
        Records any errors from the password update process.
        """
        if error is not None:
            eh.add_dev_error(
                'forgot_password',
                "There was an error updating the password. "
                "Error: " + error)
            return False
        return True

    def _get_password(
            self,
            email_text_key: str,
            username_text_key: str,
            repeat_username_text_key: str,
            username_pull_function: Union[str, Callable],
            username_pull_args: dict = None,
            password_store_function: Union[str, Callable] = None,
            password_store_args: dict = None,
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None) -> None:
        """
        Checks the validity of the entered email and username and, if
        correct, creates a new password to store and send the user.

        :param email_text_key: The st.session_state name used to access
            the email.
        :param username_text_key: The st.session_state name used to
            access the username.
        :param repeat_username_text_key: The st.session_state name used
            to access the repeated username.
        :param username_pull_function: The function to pull the username
            associated with the email. This can be a callable function
            or a string. See the docstring for forgot_username for more
            information.
        :param username_pull_args: Arguments for the
            username_pull_function. See the docstring for forgot_username
            for more information.
        :param password_store_function: The function to store the new
            password. This can be a callable function or a string. See the
            docstring for forgot_password for more information.
        :param password_store_args: Arguments for the
            password_store_function. See the docstring for
            forgot_password for more information.
        :param email_function: Provide the method for email here, this can
            be a callable function or a string. See forgot_password for
            more details.
        :param email_inputs: The inputs for the email sending process.
            See forgot_password for more details.
        :param email_creds: The credentials to use for the email API. See
            forgot_password for more details.
        """
        email = st.session_state[email_text_key]
        username = st.session_state[username_text_key]
        repeat_username = st.session_state[repeat_username_text_key]

        # make sure the email and username aren't blank
        if self._check_email_username_info(email, username, repeat_username):
            pulled_username = self._pull_username(
                email, 'forgot_password', username_pull_function,
                username_pull_args)
            # username will only be non-False if the username was pulled
            if pulled_username and pulled_username == username:
                validator = Validator()
                password = validator.generate_random_password(
                    self.weak_passwords)
                # hash password for storage
                hashed_password = Hasher([password]).generate()[0]

                # store the new credentials in case these are needed
                # outside of this function
                st.session_state[self.user_credentials_session_state] = {
                    'username': username,
                    'email': email,
                    'password': hashed_password}

                if password_store_function is not None:
                    error = self._update_password(
                        password_store_function, password_store_args,
                        username, hashed_password)
                    if self._password_update_error_handler(error):
                        if email_function is not None:
                            self._send_user_email(
                                'forgot_password', email_inputs, email,
                                email_function, email_creds, password=password)
                        else:
                            eh.clear_errors()
                elif email_function is not None:
                    self._send_user_email(
                        'forgot_password', email_inputs, email,
                        email_function, email_creds, password=password)
                else:
                    # get rid of any errors, since we have successfully
                    # updated the password
                    eh.clear_errors()

    def forgot_password(
            self,
            location: str = 'main',
            email_text_key: str = 'forgot_password_email',
            username_text_key: str = 'forgot_password_username',
            repeat_username_text_key: str = 'forgot_password_repeat_username',
            username_pull_function: Union[str, Callable] = None,
            username_pull_args: dict = None,
            password_store_function: Union[str, Callable] = None,
            password_store_args: dict = None,
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None) -> None:
        """
        Creates a forgot password form.

        :param location: The location of the login form i.e. main or
            sidebar.
        :param email_text_key: The key for the email text field. We
            attempt to default to a unique key, but you can put your own
            in here if you want to customize it or have clashes with other
            keys.
        :param username_text_key: The key for the username text field. We
            attempt to default to a unique key, but you can put your own
            in here if you want to customize it or have clashes with other
            keys.
        :param repeat_username_text_key: The key for the repeat username
            text field. We attempt to default to a unique key, but you can
            put your own in here if you want to customize it or have
            clashes with other keys.
        :param username_pull_function: The function to pull the
            username associated with the email. This can be a callable
            function or a string.

            At a minimum, a callable function should take 'email' as
            an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error' or
                'success'
             - The value should be a string that contains the error
                message when the indicator is 'dev_error' and the username
                when the indicator is 'success'. The value associated with
                'user_error' isn't used as that is the case when the
                username does not exist in the system and we don't tell
                the user that.

            The current pre-defined function types are:
                'bigquery': Pulls the username from a BigQuery table.
        :param username_pull_args: Arguments for the
            username_pull_function. This should not include 'email'
            since that will automatically be added here based on the
            user's input.

            If using 'bigquery' as your username_pull_function, the
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
            username_col (str): The name of the column in the BigQuery
                table that contains the usernames.
        :param password_store_function: The function to store the new
            password associated with the email and username. This can be a
            callable function or a string.

            At a minimum, a callable function should take 'password' as
            an argument, as well as 'username' since we can match against
            that.
            A callable function can return an error message.
             - If the password was successfully updated, the function
                should return None, as we don't want to give users too
                much info here.

            The current pre-defined function types are:
                'bigquery': Saves the credentials to a BigQuery table.

            This is only necessary if you want to save the password to
            a database or other storage location. This can be useful so
            that you can confirm the password is saved during the
            callback and handle that as necessary.
        :param password_store_args: Arguments for the
            password_store_function. This should not include 'username' or
            'password' as those will automatically be added here based on
            the user's input. Instead, it should include things like
            database name, table name, credentials to log into the
            database, etc. That way they can be compiled in this function
            and passed to the function in the callback.

            If using 'bigquery' as your password_store_function, the
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
                table that contains the passwords. The password associated
                with the given email and username will be overwritten with
                the new password.
            datetime_col (str): The name of the column in the BigQuery
                table that contains the datetime. This is used to track
                when the password was updated.
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
        # check whether the inputs are within the correct set of options
        if not self._check_form_inputs(location, 'forgot_password'):
            return False

        # set the email variables
        email_function, email_inputs, email_creds = self._define_email_vars(
            'forgot_password', email_function, email_inputs, email_creds)
        # this will return false for email_function if there was an error
        if not email_function:
            return False
        # set the username pull variables
        username_pull_function, username_pull_args = (
            self._define_save_pull_vars(
                'forgot_password', 'username_pull_args',
                username_pull_function, username_pull_args))
        # this will return false for username_pull_function if there was
        # an error
        if not username_pull_function:
            return False
        # set the password store variables
        password_store_function, password_store_args = (
            self._define_save_pull_vars(
                'forgot_password', 'password_store_args',
                password_store_function, password_store_args))
        # this will return false for password_store_function if there was
        # an error
        if not password_store_function:
            return False

        if location == 'main':
            forgot_password_form = st.form('Forgot Password')
        else:
            forgot_password_form = st.sidebar.form('Forgot Password')
        forgot_password_form.subheader('Forgot Password')

        # we need a key for email and username so they can be accessed in
        # the callback through session_state (such as st.session_state[
        # 'forgot_password_email'])
        email = forgot_password_form.text_input(
            'Email', key=email_text_key).lower()
        username = forgot_password_form.text_input(
            'Username', key=username_text_key).lower()
        repeat_username = forgot_password_form.text_input(
            'Repeat Username', key=repeat_username_text_key).lower()
        forgot_password_form.write(
            "If the email and username exists in our system, "
            "we will send you a new password.")

        forgot_password_form.form_submit_button(
            'Get Password', on_click=self._get_password,
            args=(email_text_key, username_text_key, repeat_username_text_key,
                  username_pull_function, username_pull_args,
                  password_store_function, password_store_args,
                  email_function, email_inputs, email_creds))

    def _check_store_new_info(self, store_new_info: Union[str, list]):
        """We want to make sure store_new_info is either 'any' or a string
            or list including 'email', 'username' or 'password'."""
        if ((isinstance(store_new_info, str) and
                store_new_info not in ['any', 'email', 'username',
                                       'password'])
                or (isinstance(store_new_info, list) and
                        not all([x in ['email', 'username', 'password']
                                    for x in store_new_info]))):
            eh.add_dev_error(
                'update_user_info',
                "store_new_info argument must be either 'any' or a string "
                "or list including 'email', 'username' or 'password'.")
            return False
        return True

    def _check_user_info(self, info_type: str, info: str, new_info: str,
                         repeat_new_info: str) -> bool:
        """Check whether the info is filled in, and the new info
            matches."""
        if new_info != repeat_new_info:
            eh.add_user_error(
                'update_user_info',
                "The new info does not match. Please try again.")
            return False

        validator = Validator()
        if info_type == 'username':
            if not (len(new_info) > 0 and len(repeat_new_info) > 0):
                eh.add_user_error(
                    'update_user_info',
                    "Please enter all info.")
                return False
            # the username must not already be used
            if new_info in st.session_state[self.usernames_session_state]:
                eh.add_user_error(
                    'update_user_info',
                    "Username already taken.")
                return False
            # the username must be of correct format
            if not validator.validate_username(new_info):
                eh.add_user_error(
                    'update_user_info',
                    "Username must only include letters, numbers, '-' or '_' "
                    "and be between 1 and 20 characters long.")
                return False
        elif info_type == 'email':
            if not (len(info) > 0 and len(new_info) > 0 and
                    len(repeat_new_info) > 0):
                eh.add_user_error(
                    'update_user_info',
                    "Please enter all info.")
                return False
            # the email must not already be used
            if new_info in st.session_state[self.emails_session_state]:
                eh.add_user_error(
                    'update_user_info',
                    "Email already taken, please use forgot username if "
                    "this is your email.")
                return False
            # the email must be of correct format
            if not validator.validate_email(new_info):
                eh.add_user_error(
                    'update_user_info',
                    "Email is not a valid format.")
                return False
        elif info_type == 'password':
            if not (len(info) > 0 and len(new_info) > 0 and
                    len(repeat_new_info) > 0):
                eh.add_user_error(
                    'update_user_info',
                    "Please enter all info.")
                return False
            # the password must be secure enough
            if not validator.validate_password(new_info, self.weak_passwords):
                eh.add_user_error(
                    'update_user_info',
                    "Password must be between 8 and 64 characters, contain at "
                    "least one uppercase letter, one lowercase letter, one "
                    "number, and one special character.")
                return False
        return True

    def _add_inputs_user_info_pull(
            self, info_pull_args: dict, info_type: str, username: str) -> dict:
        if info_pull_args is None:
            info_pull_args = {}
        # add the inputs to info_pull_args
        info_pull_args['type'] = info_type
        info_pull_args['username'] = username
        return info_pull_args

    def _rename_user_info_pull_args(self, info_pull_args: dict) -> dict:
        """Based on the info we want to pull, update the target and
            reference columns and reference value."""
        info_pull_args['target_col'] = info_pull_args['col_map'][
            info_pull_args['type']]
        info_pull_args['reference_col'] = info_pull_args['col_map']['username']
        info_pull_args['reference_value'] = info_pull_args['username']
        del info_pull_args['type']
        del info_pull_args['username']
        del info_pull_args['col_map']
        return info_pull_args

    def _user_info_pull_error_handler(self, info_type: str, indicator: str,
                                      value: str) -> bool:
        """ Records any errors from the user info pulling process."""
        if indicator in ('dev_error', 'user_error'):
            # a user_error would only happen if there's no info (email or
            # password) associated with the username, so this is really a
            # dev error since that should never happen
            eh.add_dev_error(
                'update_user_info',
                f"There was an error pulling the user's {info_type}. "
                f"Error: " + value)
            return False
        return True

    def _pull_user_info(
            self,
            info_type: str,
            username: str,
            info_pull_function: Union[str, Callable],
            info_pull_args: dict = None) -> Union[bool, str]:
        """
        Pulls info (either email or password) associated with the
        username.

        :param info_type: The type of data we are pulling, either 'email'
            or 'password'. This is used when defining the type of errors
            we get.
        :param username: The username to pull our info for.
        :param info_pull_function: The function to pull the info
            associated with the username. This can be a callable function
            or a string.

            At a minimum, a callable function should take 'email' as
            an argument, but can include other arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error' or
                'success'
             - The value should be a string that contains the error
                message when the indicator is 'dev_error' and the username
                when the indicator is 'success'. The value associated with
                'user_error' isn't used as that is the case when the
                username does not exist in the system and we don't tell
                the user that.

            The current pre-defined function types are:
                'bigquery': Pulls the username from a BigQuery table.
        :param info_pull_args: Arguments for the
            info_pull_function. This should not include 'info' or
            'username' since those will automatically be added here based
            on the user's inputs.

            If using 'bigquery' as your info_pull_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            col_map (dict): A dictionary mapping the info types to the
                associated column names in the database.
                {'email': email_col,
                 'username': username_col,
                 'password': password_col}
        """
        info_pull_args = self._add_inputs_user_info_pull(
            info_pull_args, info_type, username)
        # pull the info associated with the username
        if isinstance(info_pull_function, str):
            if info_pull_function.lower() == 'bigquery':
                # update the info_pull_args based on the info_type
                info_pull_args = self._rename_user_info_pull_args(
                    info_pull_args)
                db = BQTools()
                indicator, value = db.pull_value_based_on_other_col_value(
                    **info_pull_args)
            else:
                indicator, value = (
                    'dev_error',
                    "The info_pull_function method is not recognized. "
                    "The available options are: 'bigquery' or a callable "
                    "function.")
        else:
            indicator, value = info_pull_function(**info_pull_args)

        # only continue if we didn't have any issues getting the info
        if self._user_info_pull_error_handler(info_type, indicator, value):
            return value
        return False

    def _check_info_match(self, pulled_info: str, info: str,
                          info_type: str) -> bool:
        """Check that the pulled info matches the info entered."""
        if info_type != 'password' and pulled_info == info:
            return True
        elif (info_type == 'password' and
                Hasher([info]).check([pulled_info])[0]):
            return True
        else:
            eh.add_user_error(
                'update_user_info',
                f"The existing {info_type} does not match. "
                f"Please try again.")
            return False

    def _compare_user_info_to_stored(
            self, info_type: str, username: str,
            info_pull_function: Union[str, Callable],
            info_pull_args: dict, info: str) -> bool:
        """Check if the user's input matches the stored info."""
        if info_type in ('email', 'password'):
            pulled_info = self._pull_user_info(
                info_type, username, info_pull_function, info_pull_args)
            if pulled_info:
                return self._check_info_match(pulled_info, info, info_type)
            else:
                return False
        else:
            return True

    def _session_state_new_info(self, store_new_info: Union[str, list],
                                info_type: str, new_info: str,
                                info: str, username: str) -> None:
        """Replace any email or username that was in the
            'authenticator_emails' or 'authenticator_usernames' session
            states.
            If we want to store the user's new info in a session_state,
            do that here too."""
        if info_type == 'email':
            st.session_state['authenticator_emails'] = [
                new_info if x == info else x
                for x in st.session_state['authenticator_emails']]
        elif info_type == 'username':
            st.session_state['authenticator_usernames'] = [
                new_info if x == username else x
                for x in st.session_state['authenticator_usernames']]

        if (store_new_info is not None and
                (store_new_info == 'any' or
                 (isinstance(store_new_info, str) and
                  store_new_info == info_type) or
                 (isinstance(store_new_info, list) and
                  info_type in store_new_info))):
            if info_type == 'email':
                st.session_state.stauth['new_email'] = new_info
            elif info_type == 'username':
                st.session_state.stauth['new_username'] = new_info
            elif info_type == 'password':
                st.session_state.stauth['new_password'] = new_info

    def _add_inputs_user_info_update(
            self, info_store_args: dict, info: str, info_type: str,
            username: str) -> dict:
        if info_store_args is None:
            info_store_args = {}
        # add the inputs to info_store_args
        info_store_args['info'] = info
        info_store_args['type'] = info_type
        info_store_args['username'] = username
        return info_store_args

    def _rename_user_info_store_args(self, info_store_args: dict) -> dict:
        """Update the target and reference columns and reference value."""
        info_store_args['reference_col'] = info_store_args['col_map'][
            'username']
        info_store_args['reference_value'] = info_store_args[
            'username']
        info_store_args['target_col'] = info_store_args['col_map'][
            info_store_args['type']]
        info_store_args['target_value'] = info_store_args['info']
        info_store_args['datetime_col'] = info_store_args['col_map'][
            'datetime']
        del info_store_args['info']
        del info_store_args['type']
        del info_store_args['username']
        del info_store_args['col_map']
        return info_store_args

    def _update_stored_user_info(
            self, info_store_function: Union[Callable, str],
            info_store_args: dict, new_info: str,
            info_type: str, username: str) -> Union[None, str]:
        """Update user info (email or password) for the given username."""
        # first, add the info and info_type to the args
        info_store_args = self._add_inputs_user_info_update(
            info_store_args, new_info, info_type, username)
        if isinstance(info_store_function, str):
            if info_store_function.lower() == 'bigquery':
                # update the info_store_args to the correct variable names
                info_store_args = self._rename_user_info_store_args(
                    info_store_args)
                db = BQTools()
                error = db.update_value_based_on_other_col_value(
                    **info_store_args)
            else:
                error = (
                    "The info_store_function method is not recognized. "
                    "The available options are: 'bigquery' or a "
                    "callable function.")
        else:
            error = info_store_function(**info_store_args)
        return error

    def _user_info_update_error_handler(self, error: str,
                                        info_type: str) -> bool:
        """Records any errors from the user info update process."""
        if error is not None:
            eh.add_dev_error(
                'update_user_info',
                f"There was an error updating the {info_type}. "
                f"Error: " + error)
            return False
        return True

    def _pull_email_address(
            self, info_type: str, new_info: str, username: str,
            info_pull_function: Union[str, Callable],
            info_pull_args: dict) -> bool:
        """Pull the user's email address."""
        if info_type == 'email':
            return new_info
        else:
            pulled_info = self._pull_user_info(
                'email', username, info_pull_function, info_pull_args)
            if pulled_info:
                return pulled_info
            else:
                return False

    def _get_email_address_send_email(
            self, info_type: str, new_info: str, username: str,
            info_pull_function: Union[str, Callable], info_pull_args: dict,
            email_function: Union[Callable, str], email_inputs: dict,
            email_creds: dict) -> None:
        """Get the user's email address and send them en email to let them
            know their info has been updated."""
        email_address = self._pull_email_address(
            info_type, new_info, username, info_pull_function,
            info_pull_args)
        if email_address:
            self._send_user_email(
                'update_user_info', email_inputs,
                email_address, email_function, email_creds,
                info_type=info_type)

    def _update_user_info(
            self,
            select_box_key: str,
            user_info_text_key: str,
            user_info_text_key_new: str,
            user_info_text_key_new_repeat: str,
            info_pull_function: Union[str, Callable],
            info_pull_args: dict = None,
            info_store_function: Union[str, Callable] = None,
            info_store_args: dict = None,
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None,
            store_new_info: Union[str, list] = None) -> None:
        """
        Checks the validity of the entered email, username or password
        and, if correct, stores the new email, username or password and
        emails the user.

        :param select_box_key: The st.session_state name used to access
            the info type.
        :param user_info_text_key: The st.session_state name used to
            access the existing info (email or password, the username
            is assumed to be in st.session_state.stauth['username'] since
            the user should be logged in).
        :param user_info_text_key_new: The st.session_state name used
            to access the new email, username or password.
        :param user_info_text_key_new_repeat: The st.session_state name
            used to access the repeated new email, username or password.
        :param info_pull_function: The function to pull the email or
            password associated with the username. This can be a callable
            function or a string. See the docstring for update_user_info
            for more information.
        :param info_pull_args: Arguments for the info_pull_function. See
            the docstring for update_user_info for more information.
        :param info_store_function: The function to store the new info.
            This can be a callable function or a string. See the
            docstring for update_user_info for more information.
        :param info_store_args: Arguments for the info_store_function. See
            the docstring for update_user_info for more information.
        :param email_function: Provide the method for email here, this can
            be a callable function or a string. See update_user_info for
            more details.
        :param email_inputs: The inputs for the email sending process.
            See update_user_info for more details.
        :param email_creds: The credentials to use for the email API. See
            update_user_info for more details.
        :param store_new_info: A way to specify whether to store the new
            user info in a session_state. See update_user_info for more
            details.
        """
        info_type = st.session_state[select_box_key].lower()
        # this doesn't exist for username, just email and password
        if user_info_text_key in st.session_state:
            info = st.session_state[user_info_text_key]
        else:
            info = None
        new_info = st.session_state[user_info_text_key_new]
        repeat_new_info = st.session_state[user_info_text_key_new_repeat]
        username = st.session_state.stauth['username']

        # make sure the fields aren't blank
        if self._check_user_info(info_type, info, new_info, repeat_new_info):
            if info_type == 'password':
                # all passwords must be hashed
                new_info = Hasher([new_info]).generate()[0]

            # check if the user's info matches what is stored
            info_match = self._compare_user_info_to_stored(
                info_type, username, info_pull_function, info_pull_args.copy(),
                info)
            if info_match:
                # we need the old username to update the stored info but
                # the new username for the email and session_state
                if info_type == 'username':
                    existing_username = username
                    updated_username = new_info
                    st.session_state.stauth['username'] = new_info
                else:
                    existing_username = updated_username = username
                # store new_info in a session_state if desired
                self._session_state_new_info(store_new_info, info_type,
                                             new_info, info, existing_username)
                if info_store_function is not None:
                    error = self._update_stored_user_info(
                        info_store_function, info_store_args, new_info,
                        info_type, existing_username)
                    if self._user_info_update_error_handler(error, info_type):
                        if email_function is not None:
                            self._get_email_address_send_email(
                                info_type, new_info, updated_username,
                                info_pull_function, info_pull_args,
                                email_function, email_inputs, email_creds)
                        else:
                            eh.clear_errors()
                elif email_function is not None:
                    self._get_email_address_send_email(
                        info_type, new_info, updated_username,
                        info_pull_function, info_pull_args,
                        email_function, email_inputs, email_creds)
                else:
                    # get rid of any errors, since we have successfully
                    # updated the user info
                    eh.clear_errors()

    def update_user_info(
            self,
            location: str = 'main',
            select_box_key: str = 'update_user_info_selectbox',
            user_info_text_key: str = 'update_user_info_text',
            user_info_text_key_new: str = 'update_user_info_text_new',
            user_info_text_key_new_repeat: str =
                'update_user_info_text_new_repeat',
            info_pull_function: Union[str, Callable] = None,
            info_pull_args: dict = None,
            info_store_function: Union[str, Callable] = None,
            info_store_args: dict = None,
            email_function: Union[Callable, str] = None,
            email_inputs: dict = None,
            email_creds: dict = None,
            store_new_info: Union[str, list] = None) -> None:
        """
        Creates an update user info form. This allows the user to change
            their email, username or password.

        :param location: The location of the login form i.e. main or
            sidebar.
        :param select_box_key: The key for the select box that allows the
            user to choose what they want to update. We attempt to default
            to a unique key, but you can put your own in here if you want
            to customize it or have clashes with other keys.
        :param user_info_text_key: The key for the first text field, which
            is the existing email or password. We don't need the user to
            input the existing username if changing that since we assume
            the user is logged in and we can use the username from our
            session state. We attempt to default to a unique key, but you
            can put your own in here if you want to customize it or have
            clashes with other keys.
        :param user_info_text_key_new: The key for the second text field,
            which is the new email, username or password. We attempt to
            default to a unique key, but you can put your own in here if
            you want to customize it or have clashes with other keys.
        :param user_info_text_key_new_repeat: The key for the third text
            field, which is a repeat of the new email, username or
            password to confirm that it matches the second text field. We
            attempt to default to a unique key, but you can put your own
            in here if you want to customize it or have clashes with other
            keys.
        :param info_pull_function: The function to pull the email or
            password associated with the logged-in username. This can be a
            callable function or a string.

            At a minimum, a callable function should take 'info' as
            an argument, which is either 'email' or 'password' as the
            type of data to pull. It should also take 'username' as that
            is the username we will match to. And it can include other
            arguments as well.
            A callable function should return:
             - A tuple of an indicator and a value
             - The indicator should be either 'dev_error', 'user_error' or
                'success'
             - The value should be a string that contains the error
                message when the indicator is 'dev_error'  or 'user_error'
                and the email or password when the indicator is 'success'.

            The current pre-defined function types are:
                'bigquery': Pulls the info from a BigQuery table.
        :param info_pull_args: Arguments for the
            info_pull_function. This should not include 'info' or
            'username' since those will automatically be added here based
            on the user's inputs.

            If using 'bigquery' as your info_pull_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            col_map (dict): A dictionary mapping the info types to the
                associated column names in the database.
                {'email': email_col,
                 'username': username_col,
                 'password': password_col}
        :param info_store_function: The function to store the new email,
            username or password. This can be a callable function or a
            string.

            At a minimum, a callable function should take 'info' as
            an argument, as well as 'type' so we know where to look
            to update. For example, 'type' could be 'email', 'username'
            or 'password' and then the function can handle accordingly.
            A callable function can return an error message.
             - If the info was successfully updated, the function
                should return None, as we don't want to give users too
                much info here.

            The current pre-defined function types are:
                'bigquery': Saves the info to a BigQuery table.
        :param info_store_args: Arguments for the info_store_function.
            This should not include 'info' or 'type' as
            those will automatically be added here based on the user's
            input. Instead, it should include things like database
            name, table name, credentials to log into the database,
            etc. That way they can be compiled in this function and passed
            to the function in the callback.

            If using 'bigquery' as your info_store_function, the
            following arguments are required:

            bq_creds (dict): Your credentials for BigQuery, such as a
                service account key (which would be downloaded as JSON and
                then converted to a dict before using them here).
            project (str): The name of the Google Cloud project where the
                BigQuery table is located.
            dataset (str): The name of the dataset in the BigQuery table.
            table_name (str): The name of the table in the BigQuery
                dataset.
            col_map (dict): A dictionary mapping the info types to the
                associated column names in the database.
                {'email': email_col,
                 'username': username_col,
                 'password': password_col,
                 'datetime': datetime_col}
                Note that we have datetime too since we need to record
                when the info was updated.
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
        :param store_new_info: If you want to store the user's new info
            in a session_state, you can specify that here. Since storing a
            password in session_state can cause potential for dangerous
            leakage, we make the allowable values a string, so the
            developer must specify what to save. You can enter either:
            'any' or a string/list including 'email', 'username' or
            'password' to determine which will be stored when a user makes
            an update. For example, if you wanted to save just email and
            username you could do store_new_info=['email', 'username'].
            These will be stored in the following session_states:
            - email: st.session_state.stauth['new_email']
            - username: st.session_state.stauth['new_username']
            - password: st.session_state.stauth['new_password']
            Note that password will be the hashed password (not the
            original user input).
        """
        # check whether the inputs are within the correct set of options
        if (not self._check_form_inputs(location, 'update_user_info') or
                not self._check_store_new_info(store_new_info)):
            return False

        # set the email variables
        email_function, email_inputs, email_creds = self._define_email_vars(
            'update_user_info', email_function, email_inputs, email_creds)
        # this will return false for email_function if there was an error
        if not email_function:
            return False
        # set the info pull variables
        info_pull_function, info_pull_args = (
            self._define_save_pull_vars(
                'update_user_info', 'info_pull_args',
                info_pull_function, info_pull_args))
        # this will return false for info_pull_function if there was
        # an error
        if not info_pull_function:
            return False
        # set the info store variables
        info_store_function, info_store_args = (
            self._define_save_pull_vars(
                'update_user_info', 'info_store_args',
                info_store_function, info_store_args))
        # this will return false for info_store_function if there was
        # an error
        if not info_store_function:
            return False

        # we need a key for the info so they can be accessed in
        # the callback through session_state (such as st.session_state[
        # 'forgot_password_email'])
        if location == 'main':
            with st.container(border=True):
                st.subheader('Update User Info')
                info_type = st.selectbox(
                    '', ['Email', 'Username', 'Password'], key=select_box_key,
                    label_visibility='collapsed')
        else:
            with st.sidebar.container(border=True):
                st.subheader('Update User Info')
                info_type = st.selectbox(
                    '', ['Email', 'Username', 'Password'], key=select_box_key,
                    label_visibility='collapsed')

        if location == 'main':
            update_user_info_form = st.form('Update User Info')
        else:
            update_user_info_form = st.sidebar.form('Update User Info')

        if info_type == 'Email':
            info_existing = update_user_info_form.text_input(
                'Current Email', key=user_info_text_key).lower()
            info_new = update_user_info_form.text_input(
                'New Email', key=user_info_text_key_new).lower()
            info_new_repeat = update_user_info_form.text_input(
                'Repeat New Email', key=user_info_text_key_new_repeat).lower()
        elif info_type == 'Username':
            # we don't need the existing username here since it is stored
            # in st.session_state.stauth['username'] once the user is
            # logged in
            info_new = update_user_info_form.text_input(
                'New Username', key=user_info_text_key_new).lower()
            info_new_repeat = update_user_info_form.text_input(
                'Repeat New Username',
                key=user_info_text_key_new_repeat).lower()
        else:
            info_existing = update_user_info_form.text_input(
                'Current Password', key=user_info_text_key, type='password')
            info_new = update_user_info_form.text_input(
                'New Password', key=user_info_text_key_new, type='password')
            info_new_repeat = update_user_info_form.text_input(
                'Repeat New Password', key=user_info_text_key_new_repeat,
                type='password')

        update_user_info_form.form_submit_button(
            'Update Info', on_click=self._update_user_info,
            args=(select_box_key, user_info_text_key,
                  user_info_text_key_new, user_info_text_key_new_repeat,
                  info_pull_function, info_pull_args,
                  info_store_function, info_store_args,
                  email_function, email_inputs, email_creds,
                  store_new_info))

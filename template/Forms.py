"""
The StUser Forms template.

Note that many of the inputs to the methods will need to updated to
reflect the specifics of your project. This includes database info, such
as project, dataset, table and column names. It also includes website name
and email in the class instantiation and the verification url in the
register_user method.

Some of the credentials inputs that are predefined here are based on
st.secrets, which is a feature that allows you to store sensitive
information in a separate location when hosting your app on Streamlit.io.
The separate location is a TOML-type file that would have you store
'BIGQUERY' and 'SENDGRID' credentials so they can be accessed here.
"""

import streamlit as st
import stuser

from stuser import ErrorHandling as sterr


def main():
    ##########################################################
    # Set Page Title
    ##########################################################
    title_cols = st.columns(3)
    with title_cols[1]:
        title_writing = "Forms"
        title_format = f'<p style="text-align: center; font-family: ' \
                       f'Arial; font-size: 28px; ' \
                       f'font-weight: bold;">{title_writing}</p>'
        st.markdown(title_format, unsafe_allow_html=True)

    ##########################################################
    # Get Stored Data
    ##########################################################
    # get the stored usernames and emails
    db_engine = stuser.BQTools()
    usernames_indicator, saved_auth_usernames = (
        db_engine.pull_full_column_bigquery(
            bq_creds = st.secrets['BIGQUERY'],
            project = [project],
            dataset = [dataset],
            table_name = 'user_credentials',
            target_col = 'username'))
    if usernames_indicator == 'dev_errors':
        st.error(saved_auth_usernames)
        auth_usernames = []
    elif usernames_indicator == 'user_errors':
        st.error("No usernames found")
        auth_usernames = []
    else:
        auth_usernames = list(saved_auth_usernames.values)
    if 'stuser_usernames' not in st.session_state:
        st.session_state['stuser_usernames'] = auth_usernames
    emails_indicator, saved_auth_emails = (
        db_engine.pull_full_column_bigquery(
            bq_creds = st.secrets['BIGQUERY'],
            project = [project],
            dataset = [dataset],
            table_name = 'user_credentials',
            target_col = 'email'))
    if emails_indicator == 'dev_errors':
        st.error(saved_auth_emails)
        auth_emails = []
    elif emails_indicator == 'user_errors':
        st.error("No emails found")
        auth_emails = []
    else:
        auth_emails = list(saved_auth_emails.values)
    if 'stuser_emails' not in st.session_state:
        st.session_state['stuser_emails'] = auth_emails
    pre_auth_indicator, saved_pre_auth_emails = (
        db_engine.pull_full_column_bigquery(
            bq_creds = st.secrets['BIGQUERY'],
            project = [project],
            dataset = [dataset],
            table_name = 'preauthorization_codes',
            target_col = 'email'))
    if pre_auth_indicator == 'dev_errors':
        st.error(saved_pre_auth_emails)
        pre_auth_emails = []
    elif pre_auth_indicator == 'user_errors':
        st.error("No preauthorization emails found")
        pre_auth_emails = []
    else:
        pre_auth_emails = list(saved_pre_auth_emails.values)
    if 'stuser_preauthorized' not in st.session_state:
        st.session_state['stuser_preauthorized'] = pre_auth_emails

    ##########################################################
    # Class Instantiation
    ##########################################################
    try:
        stuser_forms = stuser.Forms(
            usernames_session_state='stuser_usernames',
            emails_session_state='stuser_emails',
            user_credentials_session_state='stuser_user_credentials',
            preauthorized_session_state='stuser_preauthorized',
            email_function='sendgrid',
            email_inputs={
                'website_name': [website_name],
                'website_email': [website_email]},
            email_creds={'sendgrid_api_key':
                             st.secrets['SENDGRID']['sendgrid_api_key']},
            save_pull_function='bigquery',
            save_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': [project],
                'dataset': [dataset]})
    except ValueError as e:
        # there are only dev errors for class instantiation and they
        # wouldn't need to show up ahead of time, just if they occur
        # during instantiation
        sterr.display_error('dev_errors', 'class_instantiation')
        st.stop()

    ##########################################################
    # Register User
    ##########################################################
    stuser_forms.register_user(
        'main',
        preauthorization=True,
        verify_email=True,
        email_inputs={'verification_url': [verification_url]},
        cred_save_args={'table_name': 'user_credentials'},
        auth_code_pull_args={
            'table_name': 'preauthorization_codes',
            'email_col': 'email',
            'auth_code_col': 'code'},
        incorrect_attempts=10,
        locked_hours=24,
        all_locked_args={
            'table_name': 'locked_info_register',
            'email_col': 'email',
            'locked_time_col': 'locked_time'},
        all_incorrect_attempts_args={
            'table_name': 'incorrect_attempts_register',
            'email_col': 'email',
            'datetime_col': 'datetime'})

    # FOR INSPECTION PURPOSES ONLY
    # here we display any session_state info, outside of errors, that may
    # have been updated in register_user
    if 'stuser_usernames' in st.session_state:
        st.write('stuser_usernames', st.session_state['stuser_usernames'])
    if 'stuser_emails' in st.session_state:
        st.write('stuser_emails', st.session_state['stuser_emails'])
    if 'stuser_preauthorized' in st.session_state:
        st.write('stuser_preauthorized',
                 st.session_state['stuser_preauthorized'])
    if 'stuser_user_credentials' in st.session_state:
        st.write('stuser_user_credentials',
                 st.session_state['stuser_user_credentials'])

    ##########################################################
    # Login
    ##########################################################
    st.write('---')

    if not stuser_forms.check_authentication_status():
        stuser_forms.login(
            location='main',
            check_email_verification=True,
            password_pull_args={
                'table_name': 'user_credentials',
                'username_col': 'username',
                'password_col': 'password',
                'email_verification_col': 'email_verified'},
            incorrect_attempts=10,
            locked_hours=24,
            all_locked_args={
                'table_name': 'locked_info',
                'username_col': 'username',
                'locked_time_col': 'locked_time',
                'unlocked_time_col': 'unlocked_time'},
            all_incorrect_attempts_args={
                'table_name': 'incorrect_attempts',
                'username_col': 'username',
                'datetime_col': 'datetime'})

        ##########################################################
        # Forgot Username
        ##########################################################
        with st.expander("Forgot Username"):
            stuser_forms.forgot_username(
                location='main',
                username_pull_args={
                    'table_name': 'user_credentials',
                    'email_col': 'email',
                    'username_col': 'username'})

        ##########################################################
        # Forgot Password
        ##########################################################
        with st.expander("Forgot Password"):
            stuser_forms.forgot_password(
                location='main',
                username_pull_args={
                    'table_name': 'user_credentials',
                    'email_col': 'email',
                    'username_col': 'username'},
                password_store_args={
                    'table_name': 'user_credentials',
                    'username_col': 'username',
                    'password_col': 'password',
                    'datetime_col': 'datetime'})

    else:

        st.markdown("### You are logged in!")

        ##########################################################
        # Update User Info
        ##########################################################
        with st.expander("Update User Info"):
            stuser_forms.update_user_info(
                location='main',
                info_pull_args={
                    'table_name': 'user_credentials',
                    'col_map': {'email': 'email',
                                'username': 'username',
                                'password': 'password'}},
                info_store_args={
                    'table_name': 'user_credentials',
                    'col_map': {'email': 'email',
                                'username': 'username',
                                'password': 'password',
                                'datetime': 'datetime'}},
                store_new_info='email')

        ##########################################################
        # Logout
        ##########################################################

        stuser_forms.logout()

    ##########################################################
    # FOR INSPECTION PURPOSES ONLY
    ##########################################################
    # here we display any session_state info, outside of errors, that may
    # have been updated during the login/logout/update info process
    if ('stauth' in st.session_state and 'authentication_status' in
            st.session_state.stauth.keys()):
        st.write('authentication_status',
                 st.session_state.stauth['authentication_status'])
    if ('stauth' in st.session_state and 'username' in
            st.session_state.stauth.keys()):
        st.write('username', st.session_state.stauth['username'])
    if ('stauth' in st.session_state and 'failed_login_attempts' in
            st.session_state.stauth.keys()):
        st.write('failed_login_attempts',
                 st.session_state.stauth['failed_login_attempts'])
    if ('stauth' in st.session_state and 'login_unlock' in
            st.session_state.stauth.keys()):
        st.write('login_unlock', st.session_state.stauth['login_unlock'])
    if ('stauth' in st.session_state and 'login_lock' in
            st.session_state.stauth.keys()):
        st.write('login_lock', st.session_state.stauth['login_lock'])
    if ('stauth' in st.session_state and 'new_email' in
            st.session_state.stauth.keys()):
        st.write('new_email', st.session_state.stauth['new_email'])
    if ('stauth' in st.session_state and 'new_username' in
            st.session_state.stauth.keys()):
        st.write('new_username', st.session_state.stauth['new_username'])
    if ('stauth' in st.session_state and 'new_password' in
            st.session_state.stauth.keys()):
        st.write('new_password', st.session_state.stauth['new_password'])


if __name__ == '__page__':
    main()

"""
The StUser Email Verification template.

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


def main():
    ##########################################################
    # Set Page Title
    ##########################################################
    title_cols = st.columns(3)
    with title_cols[1]:
        title_writing = "Email Verification"
        title_format = f'<p style="text-align: center; font-family: ' \
                       f'Arial; font-size: 28px; ' \
                       f'font-weight: bold;">{title_writing}</p>'
        st.markdown(title_format, unsafe_allow_html=True)

    ##########################################################
    # Verify Email
    ##########################################################
    verifier = stuser.Verification()
    try:
        verifier.verify_email(
            email_code_pull_function='bigquery',
            email_code_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': [project],
                'dataset': [dataset],
                'table_name': 'user_credentials',
                'email_col': 'email',
                'email_code_col': 'email_code'},
            verified_store_function='bigquery',
            verified_store_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': [project],
                'dataset': [dataset],
                'table_name': 'user_credentials',
                'email_col': 'email',
                'verified_col': 'email_verified',
                'datetime_col': 'datetime'})
    # let the user know if there's a key error and they don't have the
    # correct URL parameters
    except KeyError as ke:
        st.error("The expected email and authorization code are not "
                 "present. Please make sure you use the link from "
                 "the email you were sent.")
    except Exception as e:
        st.error(e)

    if ('stuser' in st.session_state and 'email_verified' in
            st.session_state.stuser and st.session_state.stuser[
                'email_verified']):
        st.success("Email Verified!\n\n"
                   "You can now login and use the website.")
    elif ('stuser' in st.session_state and 'email_verified' in
          st.session_state.stuser and not st.session_state.stuser[
                'email_verified']):
        st.error("Email Code incorrect, please try again or contact your "
                 "administrator.")


if __name__ == '__page__':
    main()

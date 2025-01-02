"""
The StUser Send Preauthorization Codes template.

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


def create_preauth_codes(emails: list):
    verifier = stuser.Verification()
    verifier.preauthorization_code(
        email=emails,
        code_store_function='bigquery',
        code_store_args={
            'bq_creds': st.secrets['BIGQUERY'],
            'project': [project],
            'dataset': [dataset],
            'table_name': 'preauthorization_codes',
            'email_col': 'email',
            'code_col': 'code'},
        email_function='sendgrid',
        email_inputs={
            'website_name': [website_name],
            'website_email': [website_email]},
        email_creds={'sendgrid_api_key':
                         st.secrets['SENDGRID']['sendgrid_api_key']})

    st.session_state['preauth_codes_sent'] = True


def main():
    ##########################################################
    # Set Page Title
    ##########################################################
    title_cols = st.columns(3)
    with title_cols[1]:
        title_writing = "Send Preauthorization Codes"
        title_format = f'<p style="text-align: center; font-family: ' \
                       f'Arial; font-size: 28px; ' \
                       f'font-weight: bold;">{title_writing}</p>'
        st.markdown(title_format, unsafe_allow_html=True)

    ##########################################################
    # Get Emails & Send Preauthorization Codes
    ##########################################################
    emails = st.text_area("Enter emails separated by commas")
    # turn into list (if no commas, still make the single email a list)
    emails = emails.split(',')
    # remove any extra spaces
    emails = [email.strip() for email in emails]

    st.button('Send Preauth Codes', on_click=create_preauth_codes,
              args=(emails,))

    if 'preauth_codes_sent' in st.session_state:
        st.success("Preauthorization Codes Sent!")


if __name__ == '__page__':
    main()

# StUser

**User registration, login and associated ecosystem for Streamlit**

## Installation

StUser can be installed via pip from [PyPI](https://pypi.org/project/stuser/):

```python
pip install stuser
```

## Contact

I would like this package to be as useful as possible, so please feel free
to reach out with any questions, comments or if you would like to
contribute. You can reach me at
[alex.melesko@msquaredds.com](mailto:alex.melesko@msquaredds.com).

## Full Example

StUser is a package that allows you to create a user registration and
login system for your Streamlit application. It is meant to be a robust
way to allow users to interact with your website securely. It has
pre-defined integrations for databases and email, and specifically defines
methods for use with GCP BigQuery and SendGrid, respectively.

### Understand Your Options

- Will you require users to be preauthorized before they can sign up? This
  is useful if you want to control who can access your application.
- Do you want users to validate their email address upon registration?
  This helps make sure the user actually has access to the email they
  are using.
- Will you lock users out after a certain number of failed login
  attempts? This is a security feature to prevent brute force attacks.

### Define User Info Storage

The first step is to define where the user info will be stored. You can
define your own storage locations and methods, but if using the
predefined BigQuery option, your dataset and tables can look like this:

![img.png](Images/BQTables.png)

This assumes that you are using all of the options available
(preauthorization, email validation, and lockout after failed attempts).
The name of the dataset and tables can vary and you can incorporate tables
into different datasets if you like, but the type of info you will store
should be the same. The _register tables are for registering when a
preauthorization code is required.

Table columns:
- incorrect_attempts:
  - username: STRING
  - datetime: DATETIME
- incorrect_attempts_register:
  - email: STRING
  - datetime: DATETIME
- locked_info:
  - username: STRING
  - locked_time: DATETIME
  - unlocked_time: DATETIME
- locked_info_register:
  - email: STRING
  - locked_time: DATETIME
- preauthorization_codes:
  - email: STRING
  - code: STRING
- user_credentials:
  - username: STRING
  - email: STRING
  - password: STRING
  - datetime: DATETIME
  - email_code: STRING
  - email_verified: BOOLEAN

### Error Handling

The package is designed to handle known errors by saving them to
session states (st.session_state). It will categorize the error as either
'user_errors' or 'dev_errors'. These categories are dictionaries where
the set of keys are the form names (such as 'login') and the values are 
the error messages. You can access these errors by using the following
syntax. Each form also has a display_error input that will automatically
display any errors above the form (after it is run) and below the form
(while it is being created).

```python
from stuser import ErrorHandling as sterr
sterr.display_error('dev_errors', 'login')
```

### Send Preauthorization Codes

If preauthorization is required, you will need to send the preauthorized
users an email with a code that they can use to register. That way someone
cannot just brute force attempt to register with emails they think would
work. This function sends an email with the code and saves the email/code
combo to a database. It should be run separately from your streamlit app.

Verification is the class that handles the verification process, both the
preauthorization codes and email verification.

Notes:
- You can have multiple emails in a list to send to multiple users at
    the same time.
- bq_creds (in code_store_args) should be a dictionary with the
    credentials for a BigQuery service account. You can add a service
    account at IAM & Admin -> Service Accounts. It should be permissioned
    to BigQuery Data Editor, BigQuery Job User and BIgQuery Read Session
    User. The fields you should have in bq_creds are: type, project_id,
    private_key_id, private_key, client_email, client_id, auth_uri,
    token_uri, auth_provider_x509_cert_url, client_x509_cert_url and
    universe_domain.
- email_inputs are used in the email body to let the user know where the 
    email is coming from.
- You will need to have registered with SendGrid and have an API key to
    include in email_creds (sendgrid_api_key) - the key is a string.

```python
verifier = stuser.Verification()
verifier.preauthorization_code(
    email=["test_user1@gmail.com",
           "test_user2@gmail.com"],
    code_store_function='bigquery',
    code_store_args={
        'bq_creds': {bq_creds},
        'project': 'project', # project name (string)
        'dataset': 'test_credentials', # whatever you called your dataset
        'table_name': 'preauthorization_codes', # whatever you called your table
        'email_col': 'email', # whatever you called your email column
        'code_col': 'code'}, # whatever you called your code column
    email_function='sendgrid',
    email_inputs={
        'website_name': 'PyPI',
        'website_email': 'hello@pypi.com'},
    email_creds={'sendgrid_api_key': 'sendgrid_api_key'})
```

### Pull Existing Users, Emails and Preauthorized Users

The existing usernames and emails are used to make sure that a new user
is not trying to register with a username or email that already exists.
The preauthorized users are used to make sure that only certain users
can register. Preauthorization is optional.

The existing usernames and emails must be loaded as lists to session
states, as that is how they are accessed by the package. It allows these
session states to be updated once a new user is added, so that subsequent
adds will take into account the new users. The preauthorized users are
also loaded as a list to a session state, since they can then be removed
once the user has registered.

Below, we rely on the BQTools class to pull the usernames. This class is
used internally in the package, but can be useful for pulling BigQuery
data in general.

```python
import streamlit as st

import stuser

db_engine = stuser.BQTools()
usernames_indicator, saved_auth_usernames = (
    db_engine.pull_full_column_bigquery(
        bq_creds ={bq_creds},
        project = 'project', # project name (string)
        dataset = 'test_credentials', # whatever you called your dataset
        table_name = 'user_credentials', # whatever you called your table
        target_col = 'username')) # whatever you called your username column
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
```

The same pattern can be used to pull the emails and preauthorized users.

### Define the Forms Object

Now that all the pre-work is done, we can instantiate the Forms.

Notes:
- The usernames, emails and preauthorized session state names should match
    those used above.
- The email and save_pull inputs can be input here to reduce the number of
    arguments needed in the Forms. This can only be done if using a
    predefined type (sendgrid and/or bigquery). As long as the email and
    save_pull inputs are the same throughout, they will not need to be
    repeated. However, some additional inputs may be needed in the
    individual widgets. For example, we don't have the table or columns
    defined in save_pull_args here since those usually vary by Form. Note
    that if any arguments are entered here and in the Forms, those in the
    Forms will override these.
- If you do not want to use the data saving or data pulling functions or
    email functions, you can ignore those inputs here. Similarly, if you
    want to use those functions in some places but not others, you can
    ignore them here and then input them in the individual widgets.    

```python
try:
    stuser_forms = stuser.Forms(
        usernames_session_state='stuser_usernames',
        emails_session_state='stuser_emails',
        user_credentials_session_state='stuser_user_credentials',
        preauthorized_session_state='stuser_preauthorized',
        email_function='sendgrid',
        email_inputs={
          'website_name': 'PyPI',
          'website_email': 'hello@pypi.com'},
        email_creds={'sendgrid_api_key': 'sendgrid_api_key'},
        save_pull_function='bigquery',
        save_pull_args={
          'bq_creds': {bq_creds},
          'project': 'project',  # project name (string)
          'dataset': 'test_credentials'})  # whatever you called your dataset
except ValueError as e:
    # there are only dev errors for class instantiation and they
    # wouldn't need to show up ahead of time, just if they occur
    # during instantiation
    sterr.display_error('dev_errors', 'class_instantiation')
    st.stop()
```

### Create a User Registration Form

Now that the Forms object is created, we can use it to create the user
registration form. This form will gather the email, username and password
(and optionally a preauthorization code). Then, optionally depending on
your inputs, it will save the credentials and send an email (which can
optionally have a verification code to verify the email).

Notes:
- For forms, the errors might be displayed after the form is submitted, so
    we want them above the form but also below the form if the errors
    happen while the form is being created. The final input in
    display_error (False below) lets the function know that it is not the
    first time this error is potentially being displayed, so it will not
    re-show an already displayed error.
- The verification url is where the user will be sent to verify their
    email address. This is the only input we need this for the email
    section since the rest was defined in the class instantiation. The
    email will include the verification url with the email and code as
    query parameters.
- cred_save_args, auth_code_pull_args, all_locked_args and
    all_incorrect_attempts_args are derived from the save_pull_args in the
    class instantiation, but we need to add the table names and columns.
- We use the all_locked_args and all_incorrect_attempts_args to pass in
    the arguments for the locking functions and incorrect attempts
    functions. This is the most efficient way, but the register_user
    function has additional variables that allow for more granular control
    if you want to save or pull differently for each step of the process.
    For example, if you wanted to save and pull in a different way than
    we have defined, you could do that with the additional variables.

```python
stuser_forms.register_user(
    'main',
    preauthorization=True,
    verify_email=True,
    email_inputs={'verification_url': 'verification_url'}, # whatever your verification url is
    cred_save_args={'table_name': 'user_credentials'},
    auth_code_pull_args={
        'table_name': 'preauthorization_codes', # whatever you called your table
        'email_col': 'email', # whatever you called your email column
        'auth_code_col': 'code'}, # whatever you called your authorization code column
    incorrect_attempts=10,
    locked_hours=24,
    all_locked_args={
        'table_name': 'locked_info_register', # whatever you called your table
        'email_col': 'email', # whatever you called your email column
        'locked_time_col': 'locked_time'}, # whatever you called your locked time column
    all_incorrect_attempts_args= {
        'table_name': 'incorrect_attempts_register', # whatever you called your table
        'email_col': 'email', # whatever you called your email column
        'datetime_col': 'datetime'}) # whatever you called your datetime column
```

### Verify User Email

If you have chosen to require email verification (verify_email=True in
register_user), you will need to create a webpage that can handle the
verification. This is a simple example of how you might do that.

Note that in email_code_pull_function, you are pulling the email code that
was saved in register_user. Therefore, it should look at whatever table
you saved to there. If using 'bigquery', that is the same table where your
credentials are stored. The verified_store_function is where you will save
whether the email is verified. Here we save it to the credentials table,
which makes it easier to check when a user is logging in.

The KeyError below is for handling when the website does not have the
query parameters in the url as expected.

```python
verifier = stuser.Verification()
try:
    verifier.verify_email(
        email_code_pull_function='bigquery',
        email_code_pull_args={
            'bq_creds': {bq_creds},
            'project': 'project',
            'dataset': 'test_credentials',
            'table_name': 'user_credentials',
            'email_col': 'email',
            'email_code_col': 'email_code'},
        verified_store_function='bigquery',
        verified_store_args={
            'bq_creds': {bq_creds},
            'project': 'project',
            'dataset': 'test_credentials',
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
```

### Login

Now that we have a user, we can create a login form. This will ask for the
user's username and password, checking that they are correct (and
that the email is verified if required). If the user has too many failed
login attempts, they will be locked out for a certain amount of time.

The first step is to check whether the user is already authorized. If they
are, we can skip the login form and go straight to the main page. We have
the authorization check as separate, so that it can be used on each page
without having to call the login form if it isn't necessary.

Notes:
- password_pull_args, all_locked_args and all_incorrect_attempts_args are
    derived from the save_pull_args in the class instantiation, but we 
    need to add the table names and columns.
- We use the all_locked_args and all_incorrect_attempts_args to pass in
    the arguments for the locking functions and incorrect attempts
    functions. This is the most efficient way, but the login
    function has additional variables that allow for more granular control
    if you want to save or pull differently for each step of the process.
    For example, if you wanted to save and pull in a different way than
    we have defined, you could do that with the additional variables.

```python
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
```

### Forgot Username

If a user forgets their username, they can enter their email address and
receive an email with their username.

Notes:
- username_pull_args is derived from the save_pull_args in the class
    instantiation, but we need to add the table names and columns.
- The email inputs were all handled in the class instantiation, so we
    don't need to add them here.

```python
stuser_forms.forgot_username(
    location='main',
    username_pull_args={
        'table_name': 'user_credentials',
        'email_col': 'email',
        'username_col': 'username'})
```

### Forgot Password

If a user forgets their password, they can enter their username and
receive an email with a new, secure password.

Notes:
- username_pull_args and password_store_args are derived from the
    save_pull_args in the class instantiation, but we need to add the
    table names and columns.
- The email inputs were all handled in the class instantiation, so we
    don't need to add them here.

```python
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
```

### Update User Info

If a user wants to update their username, password or email, they can do
so here. Usually, they will have to be logged in first to access this
form.

Notes:
- info_pull_args and info_store_args are derived from the save_pull_args
    in the class instantiation, but we need to add the table names and
    columns.
- The email inputs were all handled in the class instantiation, so we
    don't need to add them here.
- store_new_info is a string or list of strings that tells us which of the
    new info to store in a session state. So in our example, only an
    updated email would be put into a session state, whereas an updated
    username or password would not.

```python
if stuser_forms.check_authentication_status():
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
```

### Logout

Finally, once a user is logged in, we can log them out.

```python
stuser_forms.logout()
```

## Credit
This package was originally forked from [Streamlit-Authenticator](
https://github.com/mkhorasani/Streamlit-Authenticator) and so some credit
must go to the original author - Mohammad Khorasani. That is why you might
see some additional contributors in the GitHub repo for StUser. Note that
the Streamlit-Authenticator package was under an Apache license at the
time and while some of the outline was used, the code was completely
rewritten.


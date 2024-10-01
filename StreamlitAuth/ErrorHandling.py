"""
Utilities for handling errors.

We have a pattern in this package to put errors into either the
streamlit.session_state.dev_errors or
streamlit.session_state.user_errors dictionaries. Since this is
a fully streamlit-focused package, by having the errors here, the dev can
decide when and how to display them. This is a more flexible approach than
having the functions raise or write errors directly, since those errors
can either display for too short or too long a time, depending on when
the page is refreshed or other functions are called.

We separate the dev and user errors so that the dev errors can be
displayed differently or with additional information for the user, so they
know that it is a coding error and not something they did wrong.
"""

import streamlit as st


def add_dev_error(key: str, error: str) -> None:
    """
    Adds an error to the st.session_state.stauth['dev_errors'] dictionary.

    :param key: The key for the error.
    :param error: The error message to display.
    """
    if 'stauth' not in st.session_state:
        st.session_state.stauth = {}
    if 'dev_errors' not in st.session_state.stauth:
        st.session_state.stauth['dev_errors'] = {}
    st.session_state.stauth['dev_errors'][key] = error

def add_user_error(key: str, error: str) -> None:
    """
    Adds an error to the st.session_state.stauth['user_errors']
        dictionary.

    :param key: The key for the error.
    :param error: The error message to display.
    """
    if 'stauth' not in st.session_state:
        st.session_state.stauth = {}
    if 'user_errors' not in st.session_state.stauth:
        st.session_state.stauth['user_errors'] = {}
    st.session_state.stauth['user_errors'][key] = error

def clear_errors() -> None:
    """
    Clear all dev_errors and user_errors from
        streamlit.session_state.stauth.
    """
    if 'stauth' in st.session_state:
        if 'dev_errors' in st.session_state.stauth:
            st.session_state.stauth['dev_errors'] = {}
        if 'user_errors' in st.session_state.stauth:
            st.session_state.stauth['user_errors'] = {}

def display_error(error_type: str, form: str,
                  first_display: bool=True) -> None:
    """
    Displays the error message for the given error type and form. This is
    a utility that can be used outside of the form calls to display errors
    that are stored in the session state. It is useful for displaying the
    error without as much code in the main script.

    :param error_type: The type of error to display, either 'dev_errors'
        or 'user_errors'.
    :param form: The form where the error occurred, which can be:
        - 'class_instantiation'
        - 'register_user'
        - 'login'
        - 'logout'
        - 'forgot_username'
        - 'forgot_password'
        - 'update_user_info'
    :param first_display: Whether this is the first time the error could
        be displayed. This is used to determine whether the error should
        be displayed or not. If the error has already been displayed, then
        it should not be displayed again.
    """
    if 'stauth' not in st.session_state:
        st.session_state.stauth = {}
    if first_display:
        if 'displayed_errors' not in st.session_state.stauth:
            st.session_state.stauth['displayed_errors'] = {}
        if error_type not in st.session_state.stauth['displayed_errors']:
            st.session_state.stauth['displayed_errors'][error_type] = {}
        st.session_state.stauth['displayed_errors'][error_type][form] = False
        if error_type in st.session_state.stauth:
            if form in st.session_state.stauth[error_type]:
                st.error(f"{error_type}: "
                         f"{st.session_state.stauth[error_type][form]}")
                st.session_state.stauth['displayed_errors'][
                    error_type][form] = True
    else:
        if error_type in st.session_state.stauth:
            if form in st.session_state.stauth[error_type]:
                if not st.session_state.stauth['displayed_errors'][
                        error_type][form]:
                    st.error(f"{error_type}: "
                             f"{st.session_state.stauth[error_type][form]}")
                    st.session_state.stauth['displayed_errors'][
                        error_type][form] = True


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

def add_dev_error(key: str, error: str) -> None:
    """
    Adds an error to the streamlit.session_state.dev_errors dictionary.

    Parameters
    ----------
    key: str
        The key for the error.
    error: str
        The error message to display.
    """
    if 'dev_errors' not in st.session_state:
        st.session_state.dev_errors = {}
    st.session_state.dev_errors[key] = error

def add_user_error(key: str, error: str) -> None:
    """
    Adds an error to the streamlit.session_state.user_errors dictionary.

    Parameters
    ----------
    key: str
        The key for the error.
    error: str
        The error message to display.
    """
    if 'user_errors' not in st.session_state:
        st.session_state.user_errors = {}
    st.session_state.user_errors[key] = error

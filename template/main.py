"""
The main navigation and setup page for the StUser package template.
"""

import streamlit as st


def main():
    st.set_page_config(page_title="StUser Testing", layout="wide")
    title_cols = st.columns(3)
    with title_cols[1]:
        title_writing = "StUser Testing"
        title_format = f'<p style="text-align: center; font-family: ' \
                       f'Arial; font-size: 40px; ' \
                       f'font-weight: bold;">{title_writing}</p>'
        st.markdown(title_format, unsafe_allow_html=True)

    pages = [st.Page("Forms.py", title="Forms"),
             st.Page("EmailVerification.py", title="Email Verification"),
             st.Page("SendPreauthCodes.py", title="Send Preauth Codes")]
    pg = st.navigation(pages)
    pg.run()


if __name__ == '__main__':
    main()

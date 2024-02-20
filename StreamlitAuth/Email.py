import smtplib

from email.message import EmailMessage
from google.appengine.api import mail


class Email(object):
    """
    Create and send emails of different types with different services.
    """
    def __init__(self, email: str, username: str = None,
                 website_name: str = None, website_email: str = None) -> None:
        """
        :param email: The email of the user.
        :param username: The username of the user.
        :param website_name: The name of the website that is using this
            package.
        :param website_email: The email address that is sending the email.
        """
        self.email = email
        self.username = username
        self.website_name = website_name
        self.website_email = website_email

    def smtp_email_registered_user(self) -> None:
        """
        DOES NOT WORK

        Generic (SMTP) way to email the registered user to let them know
        they've registered.
        """
        msg = EmailMessage()
        msg['Subject'] = f'{self.website_name}: Thank You for Registering'
        msg['From'] = self.website_email
        msg['To'] = self.email
        msg.set_content(
            f"""Thank you for registering for {self.website_name}!\n
            You have successfully registered with the username: 
            {self.username}.\n
            If you did not register or you have any questions,
            please contact us at {self.website_email}.""")

        # Send the message via our own SMTP server.
        s = smtplib.SMTP(port=587)
        # tried with SMTP('localhost') and SMTP(port=587)
        # tried s.starttls(), s.ehlo() and s.connect(), adding one by one
        # in that order
        s.connect()
        s.starttls()
        s.ehlo()
        s.send_message(msg)
        s.quit()

    def app_engine_email_registered_user(self) -> None:
        """
        NEEDS TO BE TESTED ON APP ENGINE

        Google App Engine way to email the registered user to let them
        know they've registered. Must be used with an app hosted on
        Google App Engine.

        https://cloud.google.com/appengine/docs/standard/python3/services/mail
        """
        msg = mail.EmailMessage()
        msg.subject = f'{self.website_name}: Thank You for Registering'
        msg.sender = self.website_email
        msg.to = self.email
        msg.body = (
            f"""Thank you for registering for {self.website_name}!\n
            You have successfully registered with the username:
            {self.username}.\n
            If you did not register or you have any questions,
            please contact us at {self.website_email}.""")
        msg.send()

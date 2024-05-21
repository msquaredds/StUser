import pandas as pd

from google.cloud import bigquery
from google.oauth2 import service_account

from typing import Tuple, Union


class DBTools(object):
    """
    Interact with databases, such as saving and pulling data.
    """
    def __init__(self) -> None:
        pass

    def store_user_credentials_bigquery(
            self,
            user_credentials: dict,
            bq_creds: dict,
            project: str,
            dataset: str,
            table_name: str,
            if_exists: str = 'append') -> Union[None, str]:
        """
        Stores user credentials to Google BigQuery.

        :param user_credentials: The user credentials to store, which
            should come in with anything you need to save to bigquery,
            except for a datetime stamp, which we add here. Each key
            should just have one value associated with it, so we are only
            storing one row of data. For example, you could have:
            {'username': 'my_username', 'email': 'my_email',
            'password': 'my_password'}.
        :param bq_creds: The credentials to access the BigQuery project.
            These should, at a minimum, have the roles of "BigQuery Data
            Editor", "BigQuery Read Session User" and "BigQuery Job User".
        :param project: The project to store the data in.
        :param dataset: The dataset to store the data in.
        :param table_name: The name of the table to store the data in.
        :param if_exists: What to do if the table already exists.
            Can be 'append', 'replace', or 'fail'. Default is 'append'.
        :return: None if successful, error message if not.
        """
        # turn the user credentials into a dataframe
        for key in user_credentials:
            # create an error if the value is a list or dict
            if isinstance(user_credentials[key], (list, dict)):
                return ("Each key in user_credentials should have only one "
                        "value.")
            else:
                user_credentials[key] = [user_credentials[key]]
        # we to add a utc timestamp
        user_credentials['datetime'] = [pd.to_datetime('now', utc=True)]
        df = pd.DataFrame(user_credentials)

        # connect to the database
        scope = ['https://www.googleapis.com/auth/bigquery']
        try:
            creds = service_account.Credentials.from_service_account_info(
                bq_creds, scopes=scope)
        except Exception as e:
            return f"Error loading credentials: {str(e)}"

        try:
            client = bigquery.Client(credentials=creds)
        except Exception as e:
            return f"Error creating the BigQuery client: {str(e)}"

        # set up table_id
        table_id = project + "." + dataset + "." + table_name
        # determine behavior if table already exists
        if if_exists == 'append':
            write_disposition = 'WRITE_APPEND'
        elif if_exists == 'replace':
            write_disposition = 'WRITE_TRUNCATE'
        else:
            write_disposition = 'WRITE_EMPTY'
        # set up the config
        job_config = bigquery.LoadJobConfig(
            write_disposition=write_disposition
        )

        # store
        try:
            job = client.load_table_from_dataframe(df, table_id,
                                                   job_config=job_config)
            job.result()
        except Exception as e:
            return f"Error storing BigQuery data: {str(e)}"

        # test if we can access the table / double check that it saved
        try:
            _ = client.get_table(table_id)  # Make an API request.
        except Exception as e:
            return f"Error getting the saved table from BigQuery: {str(e)}"

    def pull_password_bigquery(
            self,
            bq_creds: dict,
            project: str,
            dataset: str,
            table_name: str,
            username_col: str,
            username: str,
            password_col: str) -> Tuple[str, str]:
        """
        Pull a password from BigQuery.

        :param bq_creds: The credentials to access the BigQuery project.
            These should, at a minimum, have the roles of "BigQuery Data
            Editor", "BigQuery Read Session User" and "BigQuery Job User".
        :param project: The project to pull the data from.
        :param dataset: The dataset to pull the data from.
        :param table_name: The table to pull the data from.
        :param username_col: The column that holds the username.
        :param username: The username to pull the password for.
        :param password_col: The column that holds the password.
        :return: A tuple with an indicator labeling the result as either
            'success' or 'error', and the password if successful or the
            error message if not.
        """
        # connect to the database
        scope = ['https://www.googleapis.com/auth/bigquery']
        try:
            creds = service_account.Credentials.from_service_account_info(
                bq_creds, scopes=scope)
        except Exception as e:
            return ('dev_errors', f"Error loading credentials: {str(e)}")

        try:
            client = bigquery.Client(credentials=creds)
        except Exception as e:
            return ('dev_errors',
                    f"Error creating the BigQuery client: {str(e)}")

        # create the query
        table_id = project + "." + dataset + "." + table_name
        sql_statement = (f"SELECT {password_col} FROM {table_id} "
                         f"WHERE {username_col} = {username}")

        import streamlit as st
        st.write("sql_statement: ", sql_statement)

        # run the query
        try:
            query_job = client.query(sql_statement)
            query_job.result()
        except Exception as e:
            return ('dev_errors', f"Error retrieving BigQuery data: {str(e)}")

        # create the df pull the first value
        df = query_job.to_dataframe()
        st.write("df: ", df)
        try:
            password = df.iloc[0, 0]
        except Exception as e:
            # we don't have a message here because this is handled by the
            # calling function - it should combine the lack of password
            # with the potential for an incorrect username and display
            # something like "Incorrect username or password."
            return ('user_errors', None)

        return ('success', password)

    def pull_full_column_bigquery(
            self,
            bq_creds: dict,
            project: str,
            dataset: str,
            table_name: str,
            target_col: str) -> Tuple[str, str]:
        """
        Pull a full column of data from BigQuery.

        Note that this method isn't currently used in Authenticated, but
        is useful for gathering usernames for a login page.

        :param bq_creds: The credentials to access the BigQuery project.
            These should, at a minimum, have the roles of "BigQuery Data
            Editor", "BigQuery Read Session User" and "BigQuery Job User".
        :param project: The project to pull the data from.
        :param dataset: The dataset to pull the data from.
        :param table_name: The table to pull the data from.
        :param target_col: The column that holds the data.
        :return: A tuple with an indicator labeling the result as either
            'success' or 'error', and the password if successful or the
            error message if not.
        """
        # connect to the database
        scope = ['https://www.googleapis.com/auth/bigquery']
        try:
            creds = service_account.Credentials.from_service_account_info(
                bq_creds, scopes=scope)
        except Exception as e:
            return ('dev_errors', f"Error loading credentials: {str(e)}")

        try:
            client = bigquery.Client(credentials=creds)
        except Exception as e:
            return ('dev_errors',
                    f"Error creating the BigQuery client: {str(e)}")

        # create the query
        table_id = project + "." + dataset + "." + table_name
        sql_statement = f"SELECT {target_col} FROM {table_id}"

        # run the query
        try:
            query_job = client.query(sql_statement)
            query_job.result()
        except Exception as e:
            return ('dev_errors', f"Error retrieving BigQuery data: {str(e)}")

        # create the df
        df = query_job.to_dataframe()
        try:
            data = df.iloc[:, 0]
        except Exception as e:
            # we don't have a message here because this is handled by the
            # calling function - it should combine the lack of password
            # with the potential for an incorrect username and display
            # something like "Incorrect username or password."
            return ('user_errors', None)

        return ('success', data)

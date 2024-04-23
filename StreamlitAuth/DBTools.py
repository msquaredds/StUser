import pandas as pd

from google.cloud import bigquery
from google.oauth2 import service_account


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
            if len(user_credentials[key]) != 1:
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

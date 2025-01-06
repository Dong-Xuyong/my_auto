import os
import pickle
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from flask import session

TOKEN_FILE = 'token.pickle'

def get_credentials():
    if 'credentials' not in session:
        return None
        
    creds_dict = session['credentials']
    creds = Credentials(
        token=creds_dict['token'],
        refresh_token=creds_dict['refresh_token'],
        token_uri=creds_dict['token_uri'],
        client_id=creds_dict['client_id'],
        client_secret=creds_dict['client_secret'],
        scopes=creds_dict['scopes']
    )
    
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        session['credentials'] = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }
        
    return creds

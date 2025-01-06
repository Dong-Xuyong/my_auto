from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from flask_executor import Executor
from datetime import datetime, timedelta
import os
import json
import base64
import re
from credentials import get_credentials

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
executor = Executor(app)

# OAuth2 client configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.send',
          'https://www.googleapis.com/auth/calendar.events']
CLIENT_SECRETS_FILE = 'client_secret.json'

def has_required_scopes(credentials):
    """Check if credentials have all required scopes"""
    if not credentials:
        return False
    granted_scopes = set(credentials.get('scopes', []))
    required_scopes = set(SCOPES)
    return required_scopes.issubset(granted_scopes)

@app.route('/')
def index():
    if 'credentials' not in session or not has_required_scopes(session['credentials']):
        return redirect(url_for('authorize'))
    return render_template('index.html')

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/auth/google'
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/auth/google')
def auth_google():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri='http://localhost:8080/auth/google'
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('index'))

def process_email(message_id):
    """Process individual email and create calendar event"""
    credentials = get_credentials()
    service = build('gmail', 'v1', credentials=credentials)
    message = service.users().messages().get(
        userId='me',
        id=message_id,
        format='full'
    ).execute()
    
    # Extract body
    if 'parts' in message['payload']:
        body = next(part['body']['data'] for part in message['payload']['parts'] if part['mimeType'] == 'text/plain')
        body = base64.urlsafe_b64decode(body).decode('utf-8')
    else:
        body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')
    
    # Extract structured information using regex
    try:
        extracted_data = {
            'competicao': re.search(r"Competição: (.*?)<br", body).group(1),
            'data_hora': re.search(r"Data/Hora: (.*?)<br", body).group(1),
            'clubes': re.search(r"Clubes: (.*?)<br", body).group(1),
            'recinto': re.search(r"Recinto de jogo: (.*?)<br", body).group(1),
            'localidade': re.search(r"Localidade: (.*?)<br", body).group(1),
            'codigo': re.search(r"Código de jogo AOL: (.*?)&nbsp;", body).group(1),
        }
        
        # Create calendar event
        calendar_service = build('calendar', 'v3', credentials=credentials)
        create_calendar_event(calendar_service, extracted_data)
    except AttributeError:
        print(f"Failed to extract data from email {message_id}")

@app.route('/emails')
def list_emails():
    credentials = get_credentials()
    service = build('gmail', 'v1', credentials=credentials)
    
    # Default filter for specific emails
    query = 'from:no.reply.afbraga.arbitragem@fpf.pt subject:"Nomeação de jogo"'
    
    results = service.users().messages().list(
        userId='me',
        maxResults=10,
        q=query
    ).execute()
    
    messages = results.get('messages', [])
    
    # Get full message details for each email
    full_messages = []
    for msg in messages:
        message = service.users().messages().get(
            userId='me',
            id=msg['id'],
            format='metadata',
            metadataHeaders=['From', 'Subject', 'Date']
        ).execute()
        
        # Print email details to console
        email_details = {
            'id': msg['id'],
            'from': next(h['value'] for h in message['payload']['headers'] if h['name'] == 'From'),
            'subject': next(h['value'] for h in message['payload']['headers'] if h['name'] == 'Subject'),
            'date': next(h['value'] for h in message['payload']['headers'] if h['name'] == 'Date')
        }
        print(f"Email ID: {email_details['id']}")
        print(f"From: {email_details['from']}")
        print(f"Subject: {email_details['subject']}")
        print(f"Date: {email_details['date']}")
        print("-" * 40)
        
        # Process email in background
        executor.submit(process_email, msg['id'])
        
        full_messages.append(email_details)
    
    return render_template('emails.html', messages=full_messages)

def check_emails_periodically():
    """Background task to check for new emails periodically"""
    with app.app_context():
        while True:
            try:
                credentials = get_credentials()
                if credentials:
                    service = build('gmail', 'v1', credentials=credentials)
                    query = 'from:no.reply.afbraga.arbitragem@fpf.pt subject:"Nomeação de jogo"'
                    results = service.users().messages().list(
                        userId='me',
                        maxResults=10,
                        q=query
                    ).execute()
                    
                    messages = results.get('messages', [])
                    for msg in messages:
                        executor.submit(process_email, msg['id'])
            except Exception as e:
                print(f"Error checking emails: {str(e)}")
            
            # Wait 5 minutes before checking again
            time.sleep(300)

# Start background task when app starts
@app.before_first_request
def start_background_tasks():
    executor.submit(check_emails_periodically)



def create_calendar_event(service, extracted_data):
    """Create a Google Calendar event from extracted email data"""
    try:
        # Parse and format the date
        dt_format = "%d-%m-%Y %H:%M"  # Expected format from email
        dt_obj = datetime.strptime(extracted_data['data_hora'], dt_format)
        iso_format = dt_obj.isoformat() + "Z"  # Convert to ISO format with UTC timezone
        
        # Calculate end time by adding 3 hours to the start time
        end_dt_obj = dt_obj + timedelta(hours=3)
        end_iso_format = end_dt_obj.isoformat() + "Z"
        
        event = {
            'summary': f"Jogo: {extracted_data['clubes']}",
            'location': f"{extracted_data['recinto']}, {extracted_data['localidade']}",
            'description': f"Competição: {extracted_data['competicao']}\nCódigo: {extracted_data['codigo']}",
            'start': {
                'dateTime': iso_format,
                'timeZone': 'Europe/Lisbon',
            },
            'end': {
                'dateTime': end_iso_format,
                'timeZone': 'Europe/Lisbon',
            },
            'reminders': {
                'useDefault': False,
                'overrides': [
                    {'method': 'popup', 'minutes': 24 * 60},  # 1 day before reminder
                ],
            },
        }
    
        event = service.events().insert(
            calendarId='primary',
            body=event
        ).execute()
        print(f"Event created: {event.get('htmlLink')}")
        return event
    except ValueError as e:
        print(f"Error parsing date: {str(e)}")
        return None
    except Exception as e:
        print(f"Error creating event: {str(e)}")
        return None


@app.route('/email/<message_id>')
def view_email(message_id):
    credentials = get_credentials()
    if not has_required_scopes(session['credentials']):
        return redirect(url_for('authorize'))
    service = build('gmail', 'v1', credentials=credentials)
    message = service.users().messages().get(
        userId='me',
        id=message_id,
        format='full'
    ).execute()
    
    # Extract headers
    headers = {h['name']: h['value'] for h in message['payload']['headers']}
    
    # Extract body
    if 'parts' in message['payload']:
        body = next(part['body']['data'] for part in message['payload']['parts'] if part['mimeType'] == 'text/plain')
        body = base64.urlsafe_b64decode(body).decode('utf-8')
    else:
        body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')
    
    # Extract structured information using regex
    extracted_data = {}
    try:
        extracted_data = {
            'competicao': re.search(r"Competição: (.*?)<br", body).group(1),
            'data_hora': re.search(r"Data/Hora: (.*?)<br", body).group(1),
            'clubes': re.search(r"Clubes: (.*?)<br", body).group(1),
            'recinto': re.search(r"Recinto de jogo: (.*?)<br", body).group(1),
            'localidade': re.search(r"Localidade: (.*?)<br", body).group(1),
            'codigo': re.search(r"Código de jogo AOL: (.*?)&nbsp;", body).group(1),
            'arbitros': re.findall(
                r"<td style='border: 1px solid black'>(.*?)</td><td style='border: 1px solid black'>(.*?)</td><td style='border: 1px solid black'>(.*?)</td><td style='border: 1px solid black'>(.*?)</td>", 
                body
            )
        }
    except AttributeError:
        # If regex fails, show raw body
        extracted_data = {'raw_body': body}

    # Create calendar event if data was extracted successfully
    if 'competicao' in extracted_data:
        calendar_service = build('calendar', 'v3', credentials=credentials)
        create_calendar_event(calendar_service, extracted_data)
    
    return render_template('email.html', 
        from_email=headers.get('From'),
        to=headers.get('To'),
        subject=headers.get('Subject'),
        date=headers.get('Date'),
        body=body,
        extracted_data=extracted_data
    )

@app.route('/send', methods=['POST'])
def send_email():
    credentials = get_credentials()
    service = build('gmail', 'v1', credentials=credentials)
    
    to = request.form['to']
    subject = request.form['subject']
    body = request.form['body']
    
    try:
        message = create_message('me', to, subject, body)
        sent_message = service.users().messages().send(
            userId='me',
            body=message
        ).execute()
        return f"Message sent. Message Id: {sent_message['id']}"
    except Exception as e:
        return f"An error occurred: {str(e)}"

def create_message(sender, to, subject, message_text):
    message = {
        'raw': base64.urlsafe_b64encode(
            f"From: {sender}\nTo: {to}\nSubject: {subject}\n\n{message_text}"
            .encode('utf-8')
        ).decode('utf-8')
    }
    return message

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run('localhost', 8080, debug=True)

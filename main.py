import base64
import hashlib
import json
import os
import urllib.parse

import requests

BASE_URL = 'https://owner-api.teslamotors.com/'
SSO_BASE_URL = 'https://auth.tesla.com/'
SSO_CLIENT_ID = 'ownerapi'
REDIRECT_URI = SSO_BASE_URL + 'void/callback'
TOKEN_URL = 'oauth2/v3/token'
CODE_URL = 'oauth2/v3/authorize'

code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=')
unencoded_digest = hashlib.sha256(code_verifier).digest()
code_challenge = base64.urlsafe_b64encode(unencoded_digest).rstrip(b'=')

auth_request_fields = {
    'response_type': 'code',
    'client_id': SSO_CLIENT_ID,
    'redirect_uri': REDIRECT_URI,
    'scope': 'openid+email+offline_access',
    'code_challenge': code_challenge.decode(),
    'code_challenge_method': 'S256',
}

url = SSO_BASE_URL + CODE_URL + '?' + '&'.join(
    f'{key}={urllib.parse.quote_plus(value)}' for key, value in auth_request_fields.items()
)
print('Open this URL:', url)
code = urllib.parse.parse_qs(urllib.parse.urlparse(input('Enter URL after authentication: ')).query)['code'][0]

post_params = {
    'grant_type': 'authorization_code',
    'client_id': SSO_CLIENT_ID,
    'redirect_uri': SSO_BASE_URL + 'void/callback',
    'code_verifier': code_verifier,
    'code': code,
}

headers = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
}

response = requests.post(SSO_BASE_URL + TOKEN_URL, post_params, headers=headers)
if response.status_code != 200:
    print('Got code', response.status_code, 'from', response.request.url)
    exit()

response_json = response.json()
with open('cache.json', 'w') as file:
    json.dump(response_json, file)

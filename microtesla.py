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


class TeslaAuth:
    def __init__(self, cache_file):
        self.__cache_file = cache_file
        self.__access_token = None

        try:
            with open(self.__cache_file) as file:
                self.__refresh_token = json.load(file)['refresh_token']
        except (FileNotFoundError, KeyError):
            self.__refresh_token = None

        self.__reauthenticate()

    def __reauthenticate(self, try_again=True):
        if self.__refresh_token is None:
            self.__get_refresh_token()
        elif try_again:
            post_params = {
                'grant_type': 'refresh_token',
                'client_id': SSO_CLIENT_ID,
                'refresh_token': self.__refresh_token,
                'scope': 'openid email offline_access',
            }

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            }

            response = requests.post(SSO_BASE_URL + TOKEN_URL, post_params, headers=headers)
            if response.status_code != 200:
                print('Got code', response.status_code, 'from', response.request.url)
                if try_again:
                    self.__refresh_token = None
                    self.__reauthenticate(False)
                    return
                else:
                    raise Exception

            response_json = response.json()
            if response_json['refresh_token'] != self.__refresh_token:
                with open('cache.json', 'w') as file:
                    json.dump(response_json, file)

            self.__refresh_token = response_json['refresh_token']
            self.__access_token = response_json['access_token']

    def __get_refresh_token(self):
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=')
        unencoded_digest = hashlib.sha256(code_verifier).digest()
        code_challenge = base64.urlsafe_b64encode(unencoded_digest).rstrip(b'=')

        auth_request_fields = {
            'response_type': 'code',
            'client_id': SSO_CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': 'openid email offline_access',
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
            'code_verifier': code_verifier,
            'code': code,
            'redirect_uri': SSO_BASE_URL + 'void/callback',
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
        if response_json['refresh_token'] != self.__refresh_token:
            with open('cache.json', 'w') as file:
                json.dump(response_json, file)

        self.__refresh_token = response_json['refresh_token']
        self.__access_token = response_json['access_token']

    def get(self, url, try_again=True):
        response = requests.get(url, headers={'Authorization': 'Bearer ' + self.__access_token})

        if response.status_code >= 300:
            print('Got code', response.status_code, 'from', response.request.url)
            if try_again:
                self.__reauthenticate()
                self.get(False)
        else:
            return response.json()


class MicroTesla:
    def __init__(self, cache_file='cache.json'):
        self.__auth = TeslaAuth(cache_file)

    def get_vehicle_list(self):
        return self.__auth.get(f'{BASE_URL}api/1/vehicles')['response']

    def get_vehicle_data(self, vehicle_id):
        return self.__auth.get(f'{BASE_URL}api/1/vehicles/{vehicle_id}/vehicle_data')['response']

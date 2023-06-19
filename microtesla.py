import binascii
import hashlib
import json
import os
import sys

import urequests

BASE_URL = 'https://owner-api.teslamotors.com/'
SSO_BASE_URL = 'https://auth.tesla.com/'
SSO_CLIENT_ID = 'ownerapi'
REDIRECT_URI = 'https%3A%2F%2Fauth.tesla.com%2Fvoid%2Fcallback'
TOKEN_URL = 'oauth2/v3/token'
CODE_URL = 'oauth2/v3/authorize'
SCOPE = 'openid+email+offline_access'

class MicroTeslaException(Exception):
    pass

class VehicleUnavailable(MicroTeslaException):
    pass


def urlsafe_b64encode(source):
    return binascii.b2a_base64(source).rstrip().replace(b'+', b'-').replace(b'/', b'_')

def generate_query_string(params):
    return '&'.join(f'{key}={value}' for key, value in params.items())

class TeslaAuth:
    def __init__(self, cache_file):
        self.__cache_file = cache_file
        self.__access_token = None

        try:
            with open(self.__cache_file) as file:
                self.__refresh_token = json.load(file)['refresh_token']
        except (OSError, KeyError):
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
                'scope': SCOPE,
            }

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            }

            response = urequests.post(SSO_BASE_URL + TOKEN_URL, data=generate_query_string(post_params), headers=headers)
            if response.status_code != 200:
                print('Got code', response.status_code, 'from', response.request.url)
                if try_again:
                    self.__refresh_token = None
                    self.__reauthenticate(False)
                    return
                else:
                    raise MicroTeslaException('failed')  # TODO
            
            response_json = response.json()
            if response_json['refresh_token'] != self.__refresh_token:
                with open('cache.json', 'w') as file:
                    json.dump(response_json, file)

            self.__refresh_token = response_json['refresh_token']
            self.__access_token = response_json['access_token']

    def __get_refresh_token(self):
        code_verifier = urlsafe_b64encode(os.urandom(32)).rstrip(b'=')
        unencoded_digest = hashlib.sha256(code_verifier).digest()
        code_challenge = urlsafe_b64encode(unencoded_digest).rstrip(b'=')

        auth_request_fields = {
            'response_type': 'code',
            'client_id': SSO_CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': SCOPE,
            'code_challenge': code_challenge.decode(),
            'code_challenge_method': 'S256',
        }
        
        print('Open this URL:', SSO_BASE_URL + CODE_URL + '?' + generate_query_string(auth_request_fields))
        
        query_string = input('Enter URL after authentication: ').split('?', 1)[1]
        code = dict(substring.split('=') for substring in query_string.split('&'))['code']

        post_params = {
            'grant_type': 'authorization_code',
            'client_id': SSO_CLIENT_ID,
            'code_verifier': code_verifier.decode(),
            'code': code,
            'redirect_uri': REDIRECT_URI,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        }

        response = urequests.post(SSO_BASE_URL + TOKEN_URL, data=generate_query_string(post_params), headers=headers)
        if response.status_code != 200:
            print('Got code', response.status_code, 'from', SSO_BASE_URL + TOKEN_URL)
            print(response.text)
            print(post_data)
            raise MicroTeslaException('failed')  # TODO

        response_json = response.json()
        if response_json['refresh_token'] != self.__refresh_token:
            with open('cache.json', 'w') as file:
                json.dump(response_json, file)

        self.__refresh_token = response_json['refresh_token']
        self.__access_token = response_json['access_token']

    def get(self, url, try_again=True):
        response = urequests.get(url, headers={'Authorization': f'Bearer {self.__access_token}', 'Connection': 'close'})
        response_text = response.text

        if response.status_code == 408:
            raise VehicleUnavailable(str(response.headers) + ' ' + response_text)
        elif response.status_code >= 300:
            print('Got code', response.status_code, 'from', url)
            if try_again:
                self.__reauthenticate()
                self.get(url, False)
            else:
                raise MicroTeslaException('failed with body ' + response_text)  # TODO
        else:
            return response.json()


class MicroTesla:
    def __init__(self, cache_file='cache.json'):
        self.__auth = TeslaAuth(cache_file)

    def get_vehicle_list(self):
        return self.__auth.get(f'{BASE_URL}api/1/vehicles')['response']
    
    def get_vehicle_summary(self, vehicle_id):
        return self.__auth.get(f'{BASE_URL}api/1/vehicles/{vehicle_id}')['response']

    def get_vehicle_data(self, vehicle_id):
        return self.__auth.get(f'{BASE_URL}api/1/vehicles/{vehicle_id}/vehicle_data')['response']

    def get_vehicle_charge_state(self, vehicle_id):
        return self.__auth.get(f'{BASE_URL}api/1/vehicles/{vehicle_id}/vehicle_data')['response']['charge_state']

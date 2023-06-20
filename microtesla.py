import binascii
import hashlib
import json
import os
import socket
import ussl

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


def query_string(params):
    return '&'.join(f'{key}={value}' for key, value in params.items())


class Request:
    def __init__(self, url, method='GET', data: bytes = None, headers: dict = None, auth: tuple = None, timeout=None):
        self.status_code = None
        self.status_text = ''
        self.headers = {}
        self.body = None

        try:
            protocol, _, host, path = url.split('/', 3)
        except ValueError:
            protocol, _, host = url.split('/', 2)
            path = ''

        if protocol not in ('http:', 'https:'):
            raise ValueError(f'Unsupported protocol: {protocol}')

        secure = protocol == 'https:'

        if ':' in host:
            host, port = host.split(":", 1)
            port = int(port)
        else:
            port = 443 if secure else 80

        (ai_family, _, ai_proto, _, ai_sock_addr) = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)[0]
        s = socket.socket(ai_family, socket.SOCK_STREAM, ai_proto)

        if timeout is not None:
            s.settimeout(timeout)

        try:
            s.connect(ai_sock_addr)
            if secure:
                s = ussl.wrap_socket(s, server_hostname=host)

            s.write(f'{method} /{path} HTTP/1.1\r\n'.encode('ascii'))

            if 'Host' not in headers:
                s.write(f'Host: {host}\r\n'.encode('ascii'))

            if auth is not None:
                s.write('Authorization: Basic '.encode('ascii'))
                s.write(binascii.b2a_base64(f'{auth[0]}:{auth[1]}'.encode('ascii'))[:-1])
                s.write('\r\n'.encode('ascii'))

            if headers is not None:
                for header, value in headers.items():
                    s.write(f'{header}: {value}\r\n'.encode('ascii'))

            if data is not None:
                s.write(f'Content-Length: {len(data)}\r\n'.encode('ascii'))

            s.write('Connection: close\r\n\r\n'.encode('ascii'))

            if data is not None:
                s.write(data)

            line = s.readline().decode('ascii').rstrip()

            try:
                _, self.status_code, self.status_text = line.split(' ', 2)
            except ValueError:
                _, self.status_code = line.split(' ', 2)

            self.status_code = int(self.status_code)

            content_length = 0
            while True:
                line = s.readline().decode('ascii').rstrip()

                if line == '':
                    break

                header, value = line.split(':', 1)

                if header.lower() == 'content-length':
                    content_length = int(value)

                self.headers[header] = value

            if content_length > 0:
                self.body = bytearray(content_length)
                data_view = memoryview(self.body)
                count = 0
                while count < content_length:
                    count += s.readinto(data_view[count:], content_length - count)
        finally:
            s.close()


class MicroTesla:
    def __init__(self, cache_file='cache.json'):
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

            url = SSO_BASE_URL + TOKEN_URL
            response = Request(url, method='POST', data=query_string(post_params).encode('utf8'), headers=headers)
            if response.status_code != 200:
                print('Got code', response.status_code, 'from', url)
                if try_again:
                    self.__refresh_token = None
                    self.__reauthenticate(False)
                    return
                else:
                    raise MicroTeslaException('failed')  # TODO

            response_json = json.loads(response.body)
            if response_json['refresh_token'] != self.__refresh_token:
                with open('cache.json', 'wb') as file:
                    file.write(response.body)

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

        print('Open this URL:', SSO_BASE_URL + CODE_URL + '?' + query_string(auth_request_fields))

        code = None
        try:
            for substring in input('Enter URL after authentication: ').split('?', 1)[1].split('&'):
                try:
                    key, value = substring.split('=', 1)
                    if key == 'code':
                        code = value
                except ValueError:
                    pass
        except (IndexError, ValueError):
            pass

        if code is None:
            raise ValueError("'code' parameter not in returned URL")

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

        url = SSO_BASE_URL + TOKEN_URL
        post_data = query_string(post_params)
        response = Request(url, method='POST', data=post_data.encode('utf8'), headers=headers)
        if response.status_code != 200:
            print('Got code', response.status_code, 'from', url)
            print(response.body)
            print(post_data)
            raise MicroTeslaException('failed')  # TODO

        response_json = json.loads(response.body)
        if response_json['refresh_token'] != self.__refresh_token:
            with open('cache.json', 'wb') as file:
                file.write(response.body)

        self.__refresh_token = response_json['refresh_token']
        self.__access_token = response_json['access_token']

    def get(self, url, try_again=True):
        response = Request(url, headers={'Authorization': f'Bearer {self.__access_token}', 'Connection': 'close'})
        response_text = response.body.decode()

        if response.status_code == 408:
            raise VehicleUnavailable(f'Vehicle is offline with error \'{response.status_code} {response.status_text}\'')
        elif response.status_code >= 400:
            print('Got code', response.status_code, 'from', url)
            if try_again:
                self.__reauthenticate()
                self.get(url, False)
            else:
                raise MicroTeslaException('failed with body ' + response_text)  # TODO
        else:
            try:
                return json.loads(response_text)
            except ValueError:
                raise MicroTeslaException('failed with body ' + response_text)

    def get_vehicle_list(self):
        return self.get(f'{BASE_URL}api/1/vehicles')['response']

    def get_vehicle_summary(self, vehicle_id):
        return self.get(f'{BASE_URL}api/1/vehicles/{vehicle_id}')['response']

    def get_vehicle_data(self, vehicle_id):
        return self.get(f'{BASE_URL}api/1/vehicles/{vehicle_id}/vehicle_data')['response']

    def get_vehicle_charge_state(self, vehicle_id):
        return self.get(f'{BASE_URL}api/1/vehicles/{vehicle_id}/vehicle_data')['response']['charge_state']

import logging
import requests
import json
import os
import base64

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

from pprint import pprint

logger = logging.getLogger(__name__)

# environment variables

# os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # enable for insecure transport


class exceptions:
    class MisMatchScope(Exception):
        def __init__(self, message="Scope mismatch"):
            self.message = message
            super().__init__(self.message)

    class InvalidToken(Exception):
        def __init__(self, message="Invalid token provided"):
            self.message = message
            super().__init__(self.message)

    class EmptyToken(Exception):
        def __init__(self, message="No token provided"):
            self.message = message
            super().__init__(self.message)


class Methods:
    def __init__(self, origin: str) -> None:
        """
        """
        credentials_filepath = os.environ["YAHOO_CREDENTIALS"]

        if not os.path.exists(credentials_filepath):
            error = "Yahoo credentials.json file not found at %s" % credentials_filepath
            logger.warning(error)

        self.credentials_filepath = credentials_filepath
        self.origin = origin
        # self.redirect_uri = f'{self.origin}/platforms/yahoo/protocols/oauth2/redirect_codes/',
        self.redirect_uri = origin
        self.authorization_base_url = 'https://api.login.yahoo.com/oauth2/request_auth'
        self.token_url = 'https://api.login.yahoo.com/oauth2/get_token'
        self.user_info_url = 'https://api.login.yahoo.com/openid/v1/userinfo'
        self.revoke_url = 'https://api.login.yahoo.com/oauth2/revoke'

        self.scopes = [
            'openid',
            # 'https://mail.yahoo.com',
            'profile',
            'email'
        ]

        with open(self.credentials_filepath) as creds_fd:
            credentials = json.load(creds_fd)
            self.client_id = credentials["client_id"]
            self.client_secret = credentials["client_secret"]

        self.yahoo = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scopes
            # client=BackendApplicationClient(client_id=self.client_id)
        )

    def authorize(self) -> str:
        """
        """
        try:
            authorization_url, state = self.yahoo.authorization_url(
                self.authorization_base_url)

            logger.info("- Successfully fetched init url")
            print(
                f"Please authorize here: {authorization_url} and State: {state}",)

            return {
                "url": authorization_url,
                "state": state  # for protection against CSFR
            }

        except Exception as error:
            logger.error("Yahoo OAuth init failed. See logs below")
            raise error

    def validate(self, code: str = None, state: str = None, redirect_response: str = None, scope: str = '') -> dict:
        """
        """
        try:
            for item in self.scopes:
                if item not in scope.split(" "):
                    logger.error("Missing score %s" % item)
                    raise exceptions.MisMatchScope()

            # redirect_response = input(
            #     "Please paste the full redirect URL here: ")

            token = None

            if (code and not redirect_response):
                token = self.yahoo.fetch_token(
                    token_url=self.token_url, client_secret=self.client_secret, authorization_response=f"{self.redirect_uri}?code={code}&state={state}" if state else f"{self.redirect_uri}?code={code}")

            elif (redirect_response):
                token = self.yahoo.fetch_token(
                    token_url=self.token_url, client_secret=self.client_secret, authorization_response=redirect_response)

            if (token):
                profile = self.yahoo.get(self.user_info_url)
                # pprint(profile.json())

                user_info = profile.json()

                logger.info("- Successfully fetched token and profile")

                return {
                    "token": dict(token),
                    "profile": {
                        "name": user_info["name"],
                        "unique_id": user_info["email"]
                    }
                }
            else:
                logger.error("No token obtained")
                raise ValueError("Token not obtained")

        except Exception as error:
            logger.error('Yahoo-OAuth2-validate failed. See logs below')
            raise error

    def refresh(self, refresh_token: str = None):
        """
        """
        try:
            # refresh_token = input("enter refresh token: ")
            if refresh_token:
                token = self.yahoo.refresh_token(
                    client_id=self.client_id, client_secret=self.client_secret, token_url=self.token_url, refresh_token=refresh_token)
                logger.info("- Successfully refreshed token")

                # pprint(token)

                return {
                    "token": dict(token)
                }
            else:
                logger.error("No token provided")
                raise exceptions.EmptyToken()

        except Exception as error:
            logger.error('Yahoo-OAuth2-validate failed. See logs below')
            raise error

    def invalidate(self, token: dict = None) -> None:
        """
        """
        try:
            token: dict = json.loads(input("enter token: "))
            # pprint(type(token))
            # pprint(token)

            encoded = base64.b64encode(
                (self.client_id + ':' + self.client_secret).encode("utf-8"))

            if 'access_token' in token:
                # print(f'bearer {token["access_token"]}')
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    # 'Authorization': f'bearer {token["access_token"]}',
                    'Authorization': f'Basic {encoded.decode("utf-8")}',
                }
                # data = {'token': token['access_token']}
                # revoke = requests.post(self.revoke_url, params={
                #                        'token': token['access_token'],
                #                        'client_id': self.client_id
                #                        }, headers=headers)

                revoke = self.yahoo.post(url=self.revoke_url,
                                         client_id=self.client_id, client_secret=self.client_secret, headers=headers)

                status_code = revoke.status_code
                print("status code: ", status_code)
                if status_code == 200:
                    print("Invalidated token")
                    logger.info("- Successfully revoked access")
                    return True
                else:
                    pprint(revoke.json())
                    raise Exception(revoke.reason)
            else:

                raise ValueError("Access token not found")

        except Exception as error:
            logger.error('Yahoo-OAuth2-revoke failed. See logs below')
            raise error

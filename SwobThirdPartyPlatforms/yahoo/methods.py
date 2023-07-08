import logging
import requests
import json
import os
import webbrowser

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

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


class Methods:
    def __init__(self, origin: str) -> None:
        """
        """
        credentials_filepath = os.environ["YAHOO_CREDENTIALS"]

        if not os.path.exists(credentials_filepath):
            error = "Yahoo credentials.json file not found at %s" % credentials_filepath
            logger.warning(error)

        self.credentials_filepath = credentials_filepath
        self.authorization_base_url = 'https://api.login.yahoo.com/oauth2/request_auth'
        self.token_url = 'https://api.login.yahoo.com/oauth2/get_token'
        # self.user_info_url = 'https://login.yahoo.com/myaccount/personalinfo'
        self.user_info_url = 'https://api.login.yahoo.com/openid/v1/userinfo'
        self.revoke_url = 'https://api.login.yahoo.com/oauth2/revoke'

        self.scopes = [
            'openid',
            # 'https://mail.yahoo.com',
            'profile',
            'email'
        ]
        self.origin = origin

        with open(self.credentials_filepath) as creds_fd:
            credentials = json.load(creds_fd)
            self.client_id = credentials["client_id"]
            self.client_secret = credentials["client_secret"]

        self.yahoo = OAuth2Session(
            client_id=self.client_id,
            # redirect_uri=f'{self.origin}/platforms/yahoo/protocols/oauth2/redirect_codes/',
            redirect_uri=self.origin,
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

    def validate(self, code: str = None, redirect_response: str = None, scope: str = '') -> dict:
        """
        """
        try:
            for item in self.scopes:
                if item not in scope.split(" "):
                    logger.error("Missing score %s" % item)
                    raise exceptions.MisMatchScope()

            redirect_response = input(
                "Please paste the full redirect URL here: ")

            token = None
            user_info = None

            # if (code):
            #     token = self.yahoo.fetch_token(
            #         token_url=self.token_url, client_secret=self.client_secret, authorization_response=redirect_response)

            # elif (redirect_response):

            # token has fields: access_token
            token = self.yahoo.fetch_token(
                token_url=self.token_url, client_secret=self.client_secret, authorization_response=redirect_response)

            pprint(type(token))
            pprint(token)

            if (token):
                profile = self.yahoo.get(self.user_info_url)
                pprint(profile.json())

                user_info = profile.json()

            logger.info("- Successfully fetched token and profile")

            return {
                "token": dict(token),
                "profile": {
                    "name": user_info["name"],
                    "unique_id": user_info["email"]
                }
            }

        except Exception as error:
            logger.error('Yahoo-OAuth2-validate failed. See logs below')
            raise error

    def refresh(self, refresh_token: str = None):
        """
        """
        try:
            refresh_token = input("enter refresh token: ")
            token = self.yahoo.refresh_token(
                client_id=self.client_id, client_secret=self.client_secret, token_url=self.token_url, refresh_token=refresh_token)
            pprint("\n\nRefreshing token")
            pprint(token)

        except Exception as error:
            logger.error('Yahoo-OAuth2-validate failed. See logs below')
            raise error

    def invalidate(self, token: dict = None) -> None:
        """
        """
        try:
            token: dict = json.loads(input("enter token: "))
            pprint(type(token))
            pprint(token)

            if 'access_token' in token:
                headers = {'content-type': 'application/x-www-form-urlencoded'}
                revoke = requests.post(self.revoke_url, params={
                                       'token': token['access_token']}, headers=headers)

                status_code = revoke.status_code
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


# if "__name__" == "__main__":
print("Testing method init")
testMethods = Methods(origin='https://moforemmanuel.github.io/blog')
print(testMethods)
print(testMethods.yahoo)
testMethods.authorize()
# webbrowser.open(testMethods.authorize()["url"])
testMethods.validate(scope="openid profile email")
# testMethods.refresh()
testMethods.invalidate()

# import logging
# import requests
# import json
# import os

# from oauthlib.oauth2 import BackendApplicationClient
# from requests_oauthlib import OAuth2Session

# logger = logging.getLogger(__name__)

# class exceptions:
#     class MisMatchScope(Exception):
#         def __init__(self, message="Scope mismatch"):
#             self.message = message
#             super().__init__(self.message)

# class Methods:
#     def __init__(self, origin:str) -> None:
#         credentials_filepath = os.environ["YAHOO_CREDENTIALS"]

#         if not os.path.exists(credentials_filepath):
#             error = "Yahoo credentials.json file not found at %s" % credentials_filepath
#             logger.warning(error)

#         self.credentials_filepath = credentials_filepath
#         self.scopes = [
#             'openid',
#             'https://mail.yahoo.com',
#             'profile'
#         ]
#         self.origin = origin
#         self.yahoo = OAuth2Session(client=BackendApplicationClient(client_id='YOUR_CLIENT_ID'))

#     def authorize(self) -> str:
#         try:
#             authorization_url, state = self.yahoo.authorization_url('https://api.login.yahoo.com/oauth2/request_auth')

#             logger.info("- Successfully fetched init url")

#             return {"url": authorization_url}

#         except Exception as error:
#             logger.error('Yahoo-OAuth2-init failed. See logs below')
#             raise error

#     def validate(self, code: str, scope: str) -> dict:
#         try:
#             for item in self.scopes:
#                 if item not in scope.split(" "):
#                     logger.error("Missing scope %s" % item)
#                     raise exceptions.MisMatchScope()

#             token = self.yahoo.fetch_token(
#                 'https://api.login.yahoo.com/oauth2/get_token',
#                 authorization_response='YOUR_REDIRECT_URI_WITH_AUTHORIZATION_CODE',
#                 client_secret='YOUR_CLIENT_SECRET'
#             )

#             logger.info("- Successfully fetched token and profile")

#             return {
#                 "token": token,
#                 "profile": {
#                     "name": "John Doe",  # Replace with actual user profile data
#                     "unique_id": "john.doe@yahoo.com"  # Replace with actual user email
#                 }
#             }

#         except Exception as error:
#             logger.error('Yahoo-OAuth2-validate failed. See logs below')
#             raise error

#     def invalidate(self, token: dict) -> None:
#         try:
#             if 'access_token' in token:
#                 revoke_url = 'https://api.login.yahoo.com/oauth2/revoke'
#                 headers = {'content-type': 'application/x-www-form-urlencoded'}
#                 revoke = requests.post(revoke_url, params={'token': token['access_token']}, headers=headers)

#                 status_code = revoke.status_code
#                 if status_code == 200:
#                     logger.info("- Successfully revoked access")
#                     return True
#                 else:
#                     raise Exception(revoke.reason)
#             else:
#
#                 raise ValueError("Access token not found")

#         except Exception as error:
#             logger.error('Yahoo-OAuth2-revoke failed. See logs below')
#             raise error

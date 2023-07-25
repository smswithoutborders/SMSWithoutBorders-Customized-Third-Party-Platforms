import logging
import json
import os
import base64
from pprint import pprint

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

import requests


logger = logging.getLogger(__name__)

# environment variables

# os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # enable for insecure transport


class exceptions:
    class MisMatchScope(Exception):
        def __init__(self, message="Scope mismatch"):
            """
            Exception raised when there is a scope mismatch.
            """
            self.message = message
            super().__init__(self.message)

    class InvalidToken(Exception):
        def __init__(self, message="Invalid token provided"):
            """
            Exception raised when an invalid token is provided.
            """
            self.message = message
            super().__init__(self.message)

    class EmptyToken(Exception):
        def __init__(self, message="No token provided"):
            """
            Exception raised when no token is provided.
            """
            self.message = message
            super().__init__(self.message)


class Methods:
    def __init__(self, origin: str) -> None:
        """
        Initialize the Methods class with the specified origin.

        Args:
            origin (str): The origin of the request.

        Raises:
            Warning: If Yahoo credentials.json file is not found at the specified path.
        """
        credentials_filepath = os.environ["YAHOO_CREDENTIALS"]

        if not os.path.exists(credentials_filepath):
            error = "Yahoo credentials.json file not found at %s" % credentials_filepath
            logger.warning(error)

        self.credentials_filepath = credentials_filepath
        self.origin = origin
        # self.redirect_uri = f"{self.origin}/platforms/yahoo/protocols/oauth2/redirect_codes/",
        self.redirect_uri = origin
        self.authorization_base_url = "https://api.login.yahoo.com/oauth2/request_auth"
        self.token_url = "https://api.login.yahoo.com/oauth2/get_token"
        self.user_info_url = "https://api.login.yahoo.com/openid/v1/userinfo"
        self.revoke_url = "https://api.login.yahoo.com/oauth2/revoke"

        self.scopes = [
            "openid",
            "profile",
            "email",
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

    def authorize(self) -> dict:
        """
        Generate the authorization URL and state.

        Returns:
            dict: A dictionary containing the authorization URL and state.

        Raises:
            Exception: If the Yahoo OAuth initialization fails.
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

    def validate(self, code: str = None, state: str = None,
                 redirect_response: str = None, scope: str = "") -> dict:
        """
        Validate the authorization code or redirect response and obtain the token and user profile.

        Args:
            code (str, optional): The authorization code. Defaults to None.
            state (str, optional): The state for protection against CSRF. Defaults to None.
            redirect_response (str, optional): The redirect response. Defaults to None.
            scope (str, optional): The requested scope. Defaults to "".

        Returns:
            dict: A dictionary containing the token and user profile information.

        Raises:
            exceptions.MisMatchScope: If there is a scope mismatch.
            ValueError: If the token is not obtained.
            Exception: If Yahoo-OAuth2-validate fails.
        """
        try:
            for item in self.scopes:
                if item not in scope.split(" "):
                    logger.error("Missing score %s" % item)
                    raise exceptions.MisMatchScope()

            token = None

            if (code and not redirect_response):
                token = self.yahoo.fetch_token(
                    token_url=self.token_url, client_secret=self.client_secret,
                    authorization_response=f"{self.redirect_uri}?code={code}&state={state}"
                    if state else f"{self.redirect_uri}?code={code}"
                )

            elif redirect_response:
                token = self.yahoo.fetch_token(
                    token_url=self.token_url, client_secret=self.client_secret,
                    authorization_response=redirect_response
                )

            if token:
                profile = self.yahoo.get(self.user_info_url)

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
            logger.error("Yahoo-OAuth2-validate failed. See logs below")
            raise error

    def refresh(self, refresh_token: str = None) -> dict:
        """
        Refreshes the Yahoo OAuth token.

        Args:
            refresh_token (str, optional): The refresh token. Defaults to None.

        Returns:
            dict: A dictionary containing the refreshed token.

        Raises:
            exceptions.EmptyToken: If no token is provided.
        """
        try:
            if refresh_token:
                token = self.yahoo.refresh_token(
                    client_id=self.client_id, client_secret=self.client_secret,
                    token_url=self.token_url, refresh_token=refresh_token
                )
                logger.info("- Successfully refreshed token")

                return {
                    "token": dict(token)
                }
            else:
                logger.error("No token provided")
                raise exceptions.EmptyToken()

        except Exception as error:
            logger.error("Yahoo-OAuth2-refresh failed. See logs below")
            raise error

    def invalidate(self, token: dict = None) -> None:
        """
        Invalidates the Yahoo OAuth token. The Yahoo team hasn't implemented this feature,
        so it won't work.

        Args:
            token (dict, optional): The token dictionary. Defaults to None.

        Returns:
            bool: True if token invalidation was successful
        Raises:
            ValueError: If the access token is not found.
        """
        try:
            client_credentials = f"{self.client_id}:{self.client_secret}"
            encoded_credentials = base64.b64encode(
                client_credentials.encode("utf-8")).decode("utf-8")

            if "access_token" in token:
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {encoded_credentials}"
                }

                data = {
                    "token": token.get("access_token"),
                    "token_type_hint": "access_token"
                }

                revoke = self.yahoo.post(
                    url=self.revoke_url, client_id=self.client_id,
                    client_secret=self.client_secret, headers=headers, data=data
                )

                status_code = revoke.status_code
                if status_code == 200:
                    logger.info("- Successfully revoked access")
                    return True
                else:
                    raise Exception(revoke.reason)
            else:

                raise ValueError("Access token not found")

        except Exception as error:
            logger.error("Yahoo-OAuth2-revoke failed. See logs below")
            raise error

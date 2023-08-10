import base64
import json
import logging
import os
from pprint import pprint

from requests_oauthlib import OAuth2Session

import requests

logger = logging.getLogger(__name__)


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
            Warning: If Discord credentials.json file is not found at the specified path.
        """
        credentials_filepath = os.environ["DISCORD_CREDENTIALS"]

        if origin.startswith("http://"):
            os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

        if not os.path.exists(credentials_filepath):
            error = "Discord credentials.json file not found at %s" % credentials_filepath
            logger.warning(error)

        self.credentials_filepath = credentials_filepath
        self.origin = origin
        # self.redirect_uri = self.origin + '/platforms/discord/protocols/oauth2/redirect_codes/'
        self.redirect_uri = origin
        self.api_base_url = 'https://discord.com/api/v10'
        self.authorization_base_url = self.api_base_url + '/oauth2/authorize'
        self.token_url = self.api_base_url + '/oauth2/token'
        self.revoke_url = self.api_base_url + '/oauth2/token/revoke'

        self.user_info_url = self.api_base_url + '/users/@me'
        self.user_guilds_url = self.api_base_url + '/users/@guilds'
        self.user_connections_url = self.api_base_url + '/users/@connections'

        self.scopes = [
            'identify',
            'email',
            'guilds',
            'messages.read',
            'connections',
        ]

        with open(self.credentials_filepath) as creds_fd:
            credentials = json.load(creds_fd)
            self.client_id = credentials["client_id"]
            self.client_secret = credentials["client_secret"]

        self.discord = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scopes,
            auto_refresh_kwargs={
                'client_id': self.client_id,
                'client_secret': self.client_secret
            },
            auto_refresh_url=self.token_url
        )

    def authorize(self) -> dict:
        """
        Generate the authorization URL and state.
        Returns:
            dict: A dictionary containing the authorization URL and state.
        Raises:
            Exception: If the Discord OAuth initialization fails.
        """
        try:
            authorization_url, state = self.discord.authorization_url(
                self.authorization_base_url)

            logger.info("- Successfully fetched init url")

            return {
                "url": authorization_url,
                "state": state  # for protection against CSFR
            }

        except Exception as error:
            logger.error("Discord OAuth init failed. See logs below")
            raise error

    def validate(self, code: str = None, state: str = None,
                 redirect_response: str = None, scope: str = "") -> dict:
        """
        Validate the authorization code or redirect response and obtain the token and user data.
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
            Exception: If Discord-OAuth2-validate fails.
        """
        try:
            for item in self.scopes:
                if item not in scope.split(" "):
                    logger.error("Missing score %s" % item)
                    raise exceptions.MisMatchScope()

            token = None

            if (code and not redirect_response):
                token = self.discord.fetch_token(
                    token_url=self.token_url, client_secret=self.client_secret,
                    authorization_response=f"{self.redirect_uri}?code={code}&state={state}"
                    if state else f"{self.redirect_uri}?code={code}"
                )

            elif redirect_response:
                token = self.discord.fetch_token(
                    token_url=self.token_url, client_secret=self.client_secret,
                    authorization_response=redirect_response
                )

            if token:
                user_info = self.discord.get(self.user_info_url).json()
                user_guilds = self.discord.get(self.user_guilds_url).json()
                user_connections = self.discord.get(
                    self.user_connections_url).json()

                pprint({"user_info": user_info, "user_guilds": user_guilds,
                       "user_connections": user_connections, "token": token})

                logger.info("- Successfully fetched token and user data")

                return {
                    "token": dict(token),
                    "profile": {
                        "name": user_info["global_name"],
                        "unique_id": user_info["email"]
                    },
                    # "user": {
                    #     "profile": {
                    #         "name": user_info["name"],
                    #         "unique_id": user_info["email"]
                    #     },
                    #     "guilds": {},
                    #     "connection": {}
                    # }
                }
            else:
                logger.error("No token obtained")
                raise ValueError("Token not obtained")

        except Exception as error:
            logger.error("Discord-OAuth2-validate failed. See logs below")
            raise error

    def refresh(self, refresh_token: str = None) -> dict:
        """
        Refreshes the Discord OAuth token.
        Args:
            refresh_token (str, optional): The refresh token. Defaults to None.
        Returns:
            dict: A dictionary containing the refreshed token.
        Raises:
            exceptions.EmptyToken: If no token is provided.
        """
        try:
            if refresh_token:
                token = self.discord.refresh_token(
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
            logger.error("Discord-OAuth2-refresh failed. See logs below")
            raise error

    def invalidate(self, token: dict = None) -> None:
        """
        Invalidates the Discord OAuth token.
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

                revoke = self.discord.post(
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
            logger.error("Discord-OAuth2-revoke failed. See logs below")
            raise error

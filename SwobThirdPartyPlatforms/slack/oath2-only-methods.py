import json
import logging
import os
from pprint import pprint

import jwt
import requests

from slack_sdk.errors import SlackApiError
from slack_sdk.oauth import OpenIDConnectAuthorizeUrlGenerator, AuthorizeUrlGenerator, RedirectUriPageRenderer
from slack_sdk.oauth.installation_store import FileInstallationStore, Installation
from slack_sdk.oauth.state_store import FileOAuthStateStore
from slack_sdk.signature import SignatureVerifier
from slack_sdk.web import WebClient


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


class OAuthMethods:
    def __init__(self, origin: str) -> None:
        """
        Initialize the OAuth Methods class with the specified origin.
        Args:
            origin (str): The origin of the request.
        Raises:
            Warning: If Slack credentials.json file is not found at the specified path.
        """
        credentials_filepath = os.environ["SLACK_CREDENTIALS"]

        if origin.startswith("http://"):
            os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

        if not os.path.exists(credentials_filepath):
            error = "Slack credentials.json file not found at %s" % credentials_filepath
            logger.warning(error)

        self.credentials_filepath = credentials_filepath
        self.origin = origin
        # self.install_uri = self.origin + '/platforms/slack/protocols/oauth2/install/'
        # self.redirect_uri = self.origin + '/platforms/slack/protocols/oauth2/redirect_codes/'
        self.install_uri = origin
        self.redirect_uri = origin

        self.scopes = [
            'openid',
            'profile',
            'email',
        ]

        with open(self.credentials_filepath) as creds_fd:
            credentials = json.load(creds_fd)
            self.client_id = credentials["client_id"]
            self.client_secret = credentials["client_secret"]

        self.state_store = FileOAuthStateStore(expiration_seconds=300)
        self.authorization_url_generator = OpenIDConnectAuthorizeUrlGenerator(
            client_id=self.client_id,
            scopes=self.scopes,
            redirect_uri=self.redirect_uri
        )
        self.redirect_page_renderer = RedirectUriPageRenderer(
            install_path=self.install_uri,
            redirect_uri_path=self.redirect_uri,
        )

    def authorize(self) -> dict:
        """
        Generate the authorization URL and state.
        Returns:
            dict: A dictionary containing the authorization URL and state.
        Raises:
            Exception: If the Slack OAuth initialization fails.
        """
        try:
            state = self.state_store.issue()
            authorization_url = self.authorization_url_generator.generate(
                state)

            logger.info("- Successfully generated init url")

            return {
                "url": authorization_url,
                "state": state  # for protection against CSFR
            }

        except Exception as error:
            logger.error("Slack OAuth init failed. See logs below")
            raise error

    def validate(self, code: str = None, state: str = None, scope: str = "") -> dict:
        """
        Validate the authorization code and obtain the token and user data.
        The user data is encoded in the user id_token, so we need to decode it.

        Args:
            code (str, optional): The authorization code. Defaults to None.
            state (str, optional): The state for protection against CSRF. Defaults to None.
            scope (str, optional): A comma separated string of the requested scopes. Defaults to "".

        Returns:
            dict: A dictionary containing the token and user profile information.

        Raises:
            exceptions.MisMatchScope: If there is a scope mismatch.
            ValueError: If the code or state is not provided.
            Exception: If Slack-OAuth2-validate fails.
        """
        try:
            for item in self.scopes:
                if item not in scope.split(","):
                    logger.error("Missing scope %s" % item)
                    raise exceptions.MisMatchScope()

            if not code:
                logger.error("No code provided")
                raise ValueError("No code provided")
            elif not state:
                logger.error("No state provided")
                raise ValueError("No state provided")
            else:
                if self.state_store.consume(state):
                    client = WebClient()  # no prepared token needed for this app
                    token_response = client.openid_connect_token(
                        client_id=self.client_id, client_secret=self.client_secret, code=code
                    )
                    # logger.info(f"openid.connect.token response: {token_response}")
                    id_token = token_response.get("id_token")
                    claims = jwt.decode(
                        id_token,
                        options={
                            "verify_signature": False
                        },
                        algorithms=["RS256"]
                    )
                    # logger.info(f"claims (decoded id_token): {claims}")

                    user_token = token_response.get("access_token")
                    user_info_response = WebClient(
                        token=user_token).openid_connect_userInfo()

                    # logger.info(f"openid.connect.userInfo response: {user_info_response}")

                    # if token rotation is enabled, we can then rotate tokens
                    # that is, exchange a long lived access token for a short lived one (12hrs),
                    # and a refresh token. This enhances security

                    # token = self.exchange(
                    #     token=token_response["access_token"])
                    # logger.info("Successfully exchanged tokens")

                    return {
                        "token": {
                            "access_token": token_response["access_token"],
                            "refresh_token": token_response["refresh_token"]
                        },
                        "profile": {
                            "name": claims["name"],
                            "unique_id": claims["email"]
                        }
                    }

        except Exception as error:
            logger.error("Slack-OAuth2-validate failed. See logs below")
            raise error

    def exchange(self, token: str = None) -> dict:
        """
        https://api.slack.com/authentication/rotation
        https://api.slack.com/authentication/rotation#exchange

        Rotates/exchanges the Slack long lives access token for a short lived
        access token and a refresh token. Token rotation has to be enabled.

        Args:
            token (str, optional): The long lived access token. Defaults to None.
        Returns:
            dict: A dictionary containing the new short lived access token and refreshed token.
        Raises:
            exceptions.EmptyToken: If no token is provided.
        """
        try:
            if token:
                client = WebClient()
                response = client.oauth_v2_exchange(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    token=token
                )
                client.auth_test()  # test auth to ensure old token not working
                # logger.info(f"token rotation/exchange response: {response}")
                logger.info("- Successfully exchanged the tokens")

                return {
                    "token": {
                        "access_token": response["access_token"],
                        "refresh_token": response["refresh_token"]
                    }
                }
            else:
                logger.error("No token provided")
                raise exceptions.EmptyToken()

        except Exception as error:
            logger.error("Slack-OAuth2-rotation failed. See logs below")
            raise error

    def refresh(self, refresh_token: str = None) -> dict:
        """
        https://api.slack.com/authentication/rotation#refresh

        Refreshes the Slack access token.
        Args:
            refresh_token (str, optional): The refresh token. Defaults to None.
        Returns:
            dict: A dictionary containing the new access token and refresh token.
        Raises:
            exceptions.EmptyToken: If no token is provided.
        """
        try:
            if refresh_token:
                client = WebClient()
                response = client.oauth_v2_access(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    grant_type='refresh_token',
                    refresh_token=refresh_token
                )
                # logger.info(f"token refresh response: {response}")
                logger.info("- Successfully refreshed the tokens")

                return {
                    "token": {
                        "access_token": response["access_token"],
                        "refresh_token": response["refresh_token"]
                    }
                }
            else:
                logger.error("No token provided")
                raise exceptions.EmptyToken()

        except Exception as error:
            logger.error("Slack-OAuth2-refresh failed. See logs below")
            raise error

    def invalidate(self, token_type_hint: str, token: str = None) -> None:
        """
        Invalidates the Slack OAuth token.
        Args:
            token (dict, optional): The token dictionary. Defaults to None.
        Returns:
            bool: True if token invalidation was successful
        Raises:
            exceptions.EmptyToken: If no token is provided.
        """
        try:
            if token:
                client = WebClient(
                    token=token
                )

                response = client.auth_revoke(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    grant_type=token_type_hint,
                    grant=token,
                    test=False
                )
                # headers = {
                #     'Authorization': f'Bearer {token}',
                #     'Content-Type': 'application/x-www-form-urlencoded'
                # }

                # response = requests.get(
                #     url='https://slack.com/api/auth.revoke',
                #     headers=headers,
                # )

                # body = response.json()

                # if not body["ok"]:
                #     logger.error(f"AN error occurred: {body['error']}")
                #     raise ValueError(body["error"])

                # logger.info(f"token revoke response: {response.json()}")
                logger.info("- Successfully revoked the token")

                return response
            else:
                logger.error("No token provided")
                raise exceptions.EmptyToken()

        except Exception as error:
            logger.error("Slack-OAuth2-revoke failed. See logs below")
            raise error

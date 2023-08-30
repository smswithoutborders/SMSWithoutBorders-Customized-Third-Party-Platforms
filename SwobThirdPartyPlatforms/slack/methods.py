import json
import logging
import os
from pprint import pprint

import jwt
import requests

from slack_sdk.errors import SlackApiError
from slack_sdk.oauth import OpenIDConnectAuthorizeUrlGenerator, AuthorizeUrlGenerator, RedirectUriPageRenderer
from slack_sdk.oauth.installation_store import FileInstallationStore,  Installation
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


class Methods:
    def __init__(self, origin: str) -> None:
        """
        Initialize the Methods class with the specified origin.
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

        self.user_scopes = [
            'chat:write',
            'channels:write',
            'groups:write',
            'im:write',
            'mpim:write',
            'channels:read',
            'groups:read',
            'im:read',
            'mpim:read'
        ]

        with open(self.credentials_filepath) as creds_fd:
            credentials = json.load(creds_fd)
            self.client_id = credentials["client_id"]
            self.client_secret = credentials["client_secret"]
            self.signing_secret = credentials["signing_secret"]

        self.state_store = FileOAuthStateStore(expiration_seconds=300)
        self.signature_verifier = SignatureVerifier(
            signing_secret=self.signing_secret)
        self.installation_store = FileInstallationStore()
        self.authorization_url_generator = AuthorizeUrlGenerator(
            client_id=self.client_id,
            user_scopes=self.user_scopes,
        )
        self.redirect_page_renderer = RedirectUriPageRenderer(
            install_path=self.install_uri,
            redirect_uri_path=self.redirect_uri,
        )

    def authorize(self) -> dict:
        """
        Generate the authorization URL and state, then install app into user's workspace
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

    def validate(self, code: str = None, state: str = None, scope: str = '') -> dict:
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
            for item in self.user_scopes:
                if item not in scope.split(","):
                    logger.error("Missing scope %s" % item)
                    raise exceptions.MisMatchScope()

            # Retrieve the auth code and state from the request params
            if not code:
                logger.error("No token obtained")
                raise ValueError("Token not obtained")
            elif not state:
                logger.error("No token obtained")
                raise ValueError("Token not obtained")
            else:
                if self.state_store.consume(state):
                    # code = request.args["code"]
                    client = WebClient()  # no prepared token needed for this app
                    oauth_response = client.oauth_v2_access(
                        client_id=self.client_id, client_secret=self.client_secret, code=code)
                    logger.info(f"oauth.v2.access response: {oauth_response}")
                    print("\n\noauth response: ", oauth_response, end='\n\n')

                    user_access_token = oauth_response["authed_user"]["access_token"]
                    user_info_response = WebClient(
                        token=user_access_token).openid_connect_userInfo()

                    print("\n\nuser information",
                          user_info_response, end="\n\n")

                    installed_enterprise = oauth_response.get(
                        "enterprise") or {}
                    is_enterprise_install = oauth_response.get(
                        "is_enterprise_install")
                    installed_team = oauth_response.get("team") or {}
                    installer = oauth_response.get("authed_user") or {}
                    incoming_webhook = oauth_response.get(
                        "incoming_webhook") or {}

                    bot_token = oauth_response.get("access_token")
                    # NOTE: oauth.v2.access doesn't include bot_id in response
                    bot_id = None
                    enterprise_url = None
                    if bot_token is not None:
                        auth_test = client.auth_test(token=bot_token)
                        bot_id = auth_test["bot_id"]
                        if is_enterprise_install is True:
                            enterprise_url = auth_test.get("url")

                    installation = Installation(
                        app_id=oauth_response.get("app_id"),
                        enterprise_id=installed_enterprise.get("id"),
                        enterprise_name=installed_enterprise.get("name"),
                        enterprise_url=enterprise_url,
                        team_id=installed_team.get("id"),
                        team_name=installed_team.get("name"),
                        bot_token=bot_token,
                        bot_id=bot_id,
                        bot_user_id=oauth_response.get("bot_user_id"),
                        bot_scopes=oauth_response.get(
                            "scope"),  # comma-separated string
                        user_id=installer.get("id"),
                        user_token=installer.get("access_token"),
                        # comma-separated string
                        user_scopes=installer.get("scope"),
                        incoming_webhook_url=incoming_webhook.get("url"),
                        incoming_webhook_channel=incoming_webhook.get(
                            "channel"),
                        incoming_webhook_channel_id=incoming_webhook.get(
                            "channel_id"),
                        incoming_webhook_configuration_url=incoming_webhook.get(
                            "configuration_url"),
                        is_enterprise_install=is_enterprise_install,
                        token_type=oauth_response.get("token_type"),
                    )

                    self.installation_store.save(installation)
                    # return self.redirect_page_renderer.render_success_page(
                    #     app_id=installation.app_id,
                    #     team_id=installation.team_id,
                    #     is_enterprise_install=installation.is_enterprise_install,
                    #     enterprise_url=installation.enterprise_url,
                    # )

                    return {
                        "token": {
                            "access_token": oauth_response["authed_user"]["access_token"],
                            "refresh_token": oauth_response["authed_user"]["refresh_token"]
                        },
                        "profile": {
                            "name": user_info_response["name"],
                            "unique_id": user_info_response["email"]
                        }
                    }

                else:
                    return self.redirect_page_renderer.render_failure_page("the state value is already expired")

            # error = request.args["error"] if "error" in request.args else ""
            # return redirect_page_renderer.render_failure_page(error)

        except Exception as error:
            logger.error("Discord-OAuth2-validate failed. See logs below")
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

    def events_subscription(self, body, timestamp, signature, command, enterprise_id=None, team_id=None, trigger_id=None, payload: dict = None):
        try:
            if not self.signature_verifier.is_valid(
                body,  # =request.get_data(),
                # =request.headers.get("X-Slack-Request-Timestamp"),
                timestamp,
                signature,  # =request.headers.get("X-Slack-Signature"),
            ):
                # return make_response("invalid request", 403)
                logger.error("Invalid Request")
                raise ValueError("Invalid request")

            if command == "/open-modal":
                try:
                    # enterprise_id = request.form.get("enterprise_id")
                    # team_id = request.form["team_id"]
                    bot = self.installation_store.find_bot(
                        enterprise_id=enterprise_id,
                        team_id=team_id,
                    )
                    bot_token = bot.bot_token if bot else None
                    if not bot_token:
                        # return make_response("Please install this app first!", 200)
                        logger.error("App not installed")
                        raise ValueError("App not installed")

                    client = WebClient(token=bot_token)
                    # trigger_id = request.form["trigger_id"]
                    response = client.views_open(
                        trigger_id=trigger_id,
                        view={
                            "type": "modal",
                            "callback_id": "modal-id",
                            "title": {"type": "plain_text", "text": "Awesome Modal"},
                            "submit": {"type": "plain_text", "text": "Submit"},
                            "close": {"type": "plain_text", "text": "Cancel"},
                            "blocks": [
                                {
                                    "type": "input",
                                    "block_id": "b-id",
                                    "label": {
                                        "type": "plain_text",
                                        "text": "Input label",
                                    },
                                    "element": {
                                        "action_id": "a-id",
                                        "type": "plain_text_input",
                                    },
                                }
                            ],
                        },
                    )
                    # return make_response("", 200)
                    logger.info("Subscription successful")
                    return

                except SlackApiError as e:
                    code = e.response["error"]
                    # return make_response(f"Failed to open a modal due to {code}", 200)
                    logger.error(e)
                    raise e

            elif payload:
                # payload = json.loads(request.form["payload"])
                if payload["type"] == "view_submission" and payload["view"]["callback_id"] == "modal-id":
                    submitted_data = payload["view"]["state"]["values"]
                    # {'b-id': {'a-id': {'type': 'plain_text_input', 'value': 'your input'}}}
                    print(submitted_data)
                    # return make_response("", 200)
                    logger.info("Subscription successful")
                    return

            # return make_response("", 404)
            logger.error("Not found")
            raise ValueError("Not found")

        except:
            logger.error("No token obtained")
            raise ValueError("Token not obtained")

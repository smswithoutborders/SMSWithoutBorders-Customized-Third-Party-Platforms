import logging
logger = logging.getLogger(__name__)

from pytwitter import Api

import json
import os

credentials_path = os.environ["TWITTER_CREDENTIALS"]

if not os.path.exists(credentials_path):
    error = "Twitter credentials.json file not found at %s" % credentials_path
    logger.warning(error)

c = open(credentials_path)
creds = json.load(c)

class Methods:
    def __init__(self, origin: str) -> None:
        """
        """
        self.credentials = creds
        self.scope=["tweet.write", "users.read", "tweet.read", "offline.access"]
        self.origin=origin
        self.twitter=Api(
                client_id=self.credentials["client_id"],
                callback_uri=f'{self.origin}/platforms/twitter/protocols/oauth2/redirect_codes/',
                scopes=self.scope,
                client_secret=self.credentials["client_secret"],
                oauth_flow=True
            )

    def authorize(self) -> str:
        """
        """
        try:
            url, code_verifier, _ = self.twitter.get_oauth2_authorize_url()

            logger.info("- Successfully fetched init url and code_verifier")

            return {"url":url, "code_verifier": code_verifier}

        except Exception as error:
            logger.error('Twitter-OAuth2-init failed. See logs below')
            raise error

    def validate(self, code: str, code_verifier: str) -> dict:
        """
        """
        try:
            resp_url = f'{self.origin}/platforms/twitter/protocols/oauth2/redirect_codes/?state=&code={code}'

            access_token = self.twitter.generate_oauth2_access_token(resp_url, code_verifier)

            api = Api(bearer_token=access_token["access_token"])

            profile = api.get_me(return_json=True)

            logger.info("- Successfully fetched token and profile")

            return {
                "token": json.dumps(access_token),
                "profile": {
                    "name": profile["data"]["name"],
                    "unique_id": profile["data"]["username"]
                }
            }

        except Exception as error:
            logger.error('Twitter-OAuth2-validate failed. See logs below')
            raise error

    def invalidate(self, token: dict) -> dict:
        """
        """
        try:
            r_token = self.refresh(token=token)

            revoke_url = "https://api.twitter.com/2/oauth2/revoke"
            oauth2_session = self.twitter._get_oauth2_session()
            result = oauth2_session.revoke_token(
                url=revoke_url,
                token=r_token["access_token"],
                token_type_hint="access_token",
            )

            logger.info("- Successfully revoked access")
            
            return result.json()
        except Exception as error:
            logger.error('Twitter-OAuth2-revoke failed. See logs below')
            raise error

    def refresh(self, token: dict) -> dict:
        """
        """
        try:
            token_url = "https://api.twitter.com/2/oauth2/token"
            oauth2_session = self.twitter._get_oauth2_session()
            refreshed_token = oauth2_session.refresh_token(
                url=token_url,
                refresh_token=token["refresh_token"],
            )

            logger.info("- Successfully refreshed token")
            
            return refreshed_token
        except Exception as error:
            logger.error('Twitter-OAuth2-refresh failed. See logs below')
            raise error
# Slack

## Linux Environment Variables

SLACK_CREDENTIALS=PATH

## Configuration

```bash
SLACK_CREDENTIALS=path/to/slack_credentials.json
```

Your slack_credentials.json file should look like

```json
{
  "client_id": "",
  "client_secret": "",
  "signing_secret": ""
}
```

### Creating and Installing your Slack App

- Head over to the [Slack API site](https://api.slack.com/apps) and create a new slack app.
- Select the workspace you want your app to be installed in.
- After your app is created, go to *OAuth & Permissions* on your sidebar menu.
- Scroll down to the **Scopes** section where we have *Bot Token Scopes* and *User Token Scopes*.
- Add the user scopes:

  - openid
  - profile
  - email

- Install the app
- If you make any more changes to the scope, be sure to reinstall your app.
- Go back to your *Auth & Permissions* page. You should be able to find where to add a callback URL. This is the URL the user will be redirected to after being authenticated.

- Grab the Client ID, Client Secret and Signing Secret of yor Slack App from the API site and add.

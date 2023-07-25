# Ymail

## Linux Environment Variables

YAHOO_CREDENTIALS=PATH

## Configuration

First, get a Consumer Key and Consumer Secret credentials by signing in at [developer.yahoo.com](https://developer.yahoo.com) and creating a project. You will use these credentials for later calls in the OAuth 2.0 flow.

See this [guide](https://developer.yahoo.com/oauth2/guide/flows_authcode/) for more info

Set YAHOO_CREDENTIALS Environment Variable to path of your credentials file (a json file containing the `client_id` and `client_secret`).

```bash
YAHOO_CREDENTIALS=path/to/yahoo_credentials.json
```

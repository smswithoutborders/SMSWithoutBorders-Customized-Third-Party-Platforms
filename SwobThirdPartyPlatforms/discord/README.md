# Discord

## Linux Environment Variables

DISCORD_CREDENTIALS=PATH

## Configuration

First, get a Client ID and Client Secret credentials by signing in at [https://discord.com/developers](https://discord.com/developers) and creating a project at [https://discord.com/developers/applications](https://discord.com/developers/applications). You will use these credentials in the OAuth 2.0 flow.

Set DISCORD_CREDENTIALS Environment Variable to path of your credentials file (a json file containing the `client_id` and `client_secret`).

```bash
DISCORD_CREDENTIALS=path/to/discord_credentials.json
```

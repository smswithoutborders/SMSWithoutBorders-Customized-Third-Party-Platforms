# Telegram

## Linux Environment Variables

TELEGRAM_CREDENTIALS=PATH
TELEGRAM_RECORDS=PATH

## Configuration

Get your credentials from [Telegram Developer Portal](https://my.telegram.org/). Set TELEGRAM_CREDENTIALS Environment Variable to path of your credentials file.

```bash
TELEGRAM_CREDENTIALS=path/to/telegram_credentials.json
TELEGRAM_RECORDS=path/to/telegram_records
```

Your telegram_credentials.json file should look like

```json
{
  "api_id": "",
  "api_hash": ""
}
```

## SMSwithoutBorders-customplatform-Python

## Requirements

- [Python](https://www.python.org/) (version >= [3.8.10](https://www.python.org/downloads/release/python-3810/))
- [Python Virtual Environments](https://docs.python.org/3/tutorial/venv.html)

## Installation

Create a Virtual Environments **(venv)**

```
python3 -m venv venv
```

Move into Virtual Environments workspace

```
. venv/bin/activate
```

Install all python packages

```
python -m pip install -r requirements.txt
```

## How to use

### Run script

```bash
python3 src/twitter.py
```

### Test

Test scripts are found in the dir `test/`.

The test attempts to acquire your token and stores in the path:

`test/token.json`

To run the test, you will need your credentials.json which should look like

```json
{
  "client_id": "",
  "client_secret": "",
  "redirect_uri": "https://localhost:9000/callback"
}
```

Place the credentials file in the test/ directory (make sure the file is called credentials.json).

Be sure to have the `redirect_uri` added to list of redirect origins in your twitter developers portal.

To run the test and acquire the token file only.

```bash
python3 test/get_token.py
```

<img src="https://github.com/smswithoutborders/SMSWithoutBorders-Resources/raw/master/multimedia/img/swob_logo_icon.png" align="right" width="350px"/>

# SMSWithoutBorders-Customized-Third-Party-Platforms

SMSWithoutBorders Third Party Platforms library

## Installation

Please make sure you have Python 3.7 or newer (python --version).

### Create a Virtual Environments

```bash
$ python3 -m venv venv
$ . venv/bin/activate
```

### PyPI

```bash
$ pip install --upgrade pip wheel
$ pip install "git+https://github.com/smswithoutborders/SMSWithoutBorders-Customized-Third-Party-Platforms.git@main#egg=SwobThirdPartyPlatforms"
```

Install upgrades

```bash
$ pip install --force-reinstall "git+https://github.com/smswithoutborders/SMSWithoutBorders-Customized-Third-Party-Platforms.git@main#egg=SwobThirdPartyPlatforms"
```

### From source

```bash
$ git clone https://github.com/smswithoutborders/SMSWithoutBorders-Customized-Third-Party-Platforms.git
$ cd SMSWithoutBorders-Customized-Third-Party-Platforms
$ python3 setup.py install
```

## Supported Platforms

1. [Gmail](./SwobThirdPartyPlatforms/gmail/README.md)
2. [Twitter](./SwobThirdPartyPlatforms/twitter/README.md)
3. [Telegram](./SwobThirdPartyPlatforms/telegram/README.md)

## Usage

### Table of Content

---

1. [Initialize Platform methods](#methods)
2. [Initialize Platform execute](#methods)
3. [Get Platform Information](#information)

---

### methods

```python
from SwobThirdPartyPlatforms import ImportPlatform
from SwobThirdPartyPlatforms.exceptions import PlatformDoesNotExist

try
    # Import platform
    Platform = ImportPlatform(platform_name="platform_name")

    # Initialize OAuth2 Methods
    Methods = Platform.methods(origin = "origin")
    # Initialize TwoFactor Methods
    Methods = Platform.methods(identifier = "identifier")

    try
        # authorization
        authorization_result = Methods.authorize()

        # validation
        validation_result = Methods.validate(
            code=code,
            scope=scope,
            code_verifier=code_verifier
        )

        # invalidation
        Methods.invalidate(token=token)

    except Platform.exceptions.<some platform exception>

except PlatformDoesNotExist as error:
    # Do something

except Exception as error:
    # Do something
```

### execute

```python
from SwobThirdPartyPlatforms import ImportPlatform
from SwobThirdPartyPlatforms.exceptions import PlatformDoesNotExist

try
    # Import platform
    Platform = ImportPlatform(platform_name="platform_name")

    # run execute function
    Platform.execute(body=body, user_details=user_details)

except PlatformDoesNotExist as error:
    # Do something

except Exception as error:
    # Do something
```

### information

```python
from SwobThirdPartyPlatforms import ImportPlatform
from SwobThirdPartyPlatforms.exceptions import PlatformDoesNotExist

try
    # Import platform
    Platform = ImportPlatform(platform_name="platform_name")

    # get platform information
    platform_information = Platform.info

except PlatformDoesNotExist as error:
    # Do something

except Exception as error:
    # Do something
```

## Exceptions

- **PlatformDoesNotExist**: Exception raised when Platform is not Found.

  _return:_ String

## Licensing

This project is licensed under the [GNU General Public License v3.0](LICENSE).

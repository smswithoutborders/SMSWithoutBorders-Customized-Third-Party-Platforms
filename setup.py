import os
from setuptools import find_packages, setup

f = open(os.path.join(os.path.dirname(__file__), "README.md"))
readme = f.read()
f.close()

setup(
    name="SwobThirdPartyPlatforms",
    packages=find_packages(),
    version="0.1.1",
    description="SMSWithoutBorders Third-Party Platforms library",
    long_description=readme,
    author="Afkanerd",
    author_email="developers@smswithoutborders.com",
    license="The GNU General Public License v3.0",
    install_requires=[
        "requests~=2.28.1",
        "google-api-python-client~=2.66.0",
        "google-auth-httplib2~=0.1.0",
        "google-auth-oauthlib~=0.4.3",
        "Telethon~=1.24.0",
        "python-twitter-v2~=0.7.7",
        "tweepy~=4.8.0",
    ],
    package_data={"": ["info.json", "*-icon.svg"]},
    include_package_data=True,
    test_suite="tests",
)

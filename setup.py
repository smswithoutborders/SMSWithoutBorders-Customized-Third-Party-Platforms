"""
SwobThirdPartyPlatforms setup file.

This file defines the package metadata and dependencies for the SwobThirdPartyPlatforms package.

Author: Afkanerd <developers@smswithoutborders.com>
License: GNU General Public License v3.0
"""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as file_:
    readme = file_.read()

setup(
    name="SwobThirdPartyPlatforms",
    version="0.2.0",
    description="SMSWithoutBorders Third-Party Platforms Library",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Afkanerd",
    author_email="developers@smswithoutborders.com",
    license="GNU General Public License v3.0",
    packages=find_packages(),
    package_data={"": ["info.json", "*-icon.svg"]},
    install_requires=[
        "requests~=2.28.1",
        "google-api-python-client~=2.66.0",
        "google-auth-httplib2~=0.1.0",
        "google-auth-oauthlib~=0.4.3",
        "Telethon~=1.24.0",
        "python-twitter-v2~=0.7.7",
        "tweepy~=4.8.0",
    ],
    test_suite="tests",
)

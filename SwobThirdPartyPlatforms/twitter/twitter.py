#!/usr/bin/env python3

import sys
import tweepy
import math
import textwrap
import logging

def post_tweet(access_token: str, tweet: str)->None:
    """
    """
    try:
        client = tweepy.Client(access_token)
    except Exception as error:
        raise error
    else:
        try:
            # max length of tweet
            tweet_max = 280
            # obtain length of tweet
            tweet_length = len(tweet)

            # check length
            if tweet_length <= tweet_max:
                client.create_tweet(text=tweet, user_auth=False)
                return True

            elif tweet_length >= tweet_max:
                # divided tweet_length / 280
                # You might consider adjusting this down 
                # depending on how you want to format the 
                # tweet.
                tweet_threads_required = math.ceil(tweet_length / tweet_max)

                # determine the number of tweets 
                tweet_per_thread = math.ceil(tweet_length / tweet_threads_required)

                # chunk the tweet into individual pieces
                tweets = textwrap.wrap(tweet, 
                        tweet_per_thread, break_long_words=False)

                tweet_id = None
                for x, tweet in zip(range(len(tweets)), tweets):
                    if x == 0:
                        # send first tweet and get the tweet_id
                        response = client.create_tweet(text=tweet, user_auth=False)
                        tweet_id = response.data["id"]
                    else:
                        # send subsequent tweets in reply to the previous tweet_id
                        response = client.create_tweet(text=tweet, 
                                in_reply_to_tweet_id=tweet_id, user_auth=False)
                        tweet_id = response.data["id"]

        except Exception as error:
            raise error

def execute(body: str, user_details: dict) -> None:
    """
    """
    logging.debug(user_details)

    access_token = user_details['token']['access_token']
    try:
        post_tweet(access_token=access_token, tweet=body)
    except Exception as error:
        raise error

if __name__ == "__main__":
    # Place token object here 
    token = {}

    sample_tweet = 'SMS technology originated from radio telegraphy in radio memo pagers that used standardized phone protocols. These were defined in 1986 as part of the Global System for Mobile Communications (GSM) series of standards.[2] The first test SMS message was sent on December 3, 1992, when Neil Papworth, a test engineer for Sema Group, used a personal computer to send "Merry Christmas" to the phone of colleague Richard Jarvis.[3] SMS rolled out commercially on many cellular networks that decade and became hugely popular worldwide as a method of text communication.[4] By the end of 2010, SMS was the most widely used data application, with an estimated 3.5 billion active users, or about 80% of all mobile phone subscribers.'

    post_tweet(tweet=sample_tweet, access_token=sys.argv[1])


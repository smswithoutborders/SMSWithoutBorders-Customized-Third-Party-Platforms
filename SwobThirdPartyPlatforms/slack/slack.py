import logging
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


client = WebClient(token=os.environ.get("SLACK_BOT_TOKEN"))
logger = logging.getLogger(__name__)


def get_channels(token: str, is_channel: bool = False, is_group: bool = False, is_im: bool = False):
    """
    Gets all user's channels (channels, groups and instant messages)

    Args:
        token (str): User's access token
        is_channel (bool, optional): Boolean flag for filtering channels of type channel
        is_group (bool, optional): Boolean flag for filtering channels of type group
        is_im (bool, optional): Boolean flag for filtering channels of type im (instant messages)

    Returns:
        list: All the filtered channel objects. If no filter passed, returns all channels

    Raises:
        SlackApiError: Any error that occurs with the Slack API
    """
    client = WebClient(token=token)
    channels = []

    try:
        # Call the conversations.list method using the WebClient
        for result in client.conversations_list():
            for channel in result.get("channels"):
                # Check if the channel matches the specified criteria
                if (
                    (is_channel and channel["is_channel"]) or
                    (is_group and channel["is_group"]) or
                    (is_im and channel["is_im"])
                ):
                    channels.append(channel)

        # If none of the boolean arguments are True, return all channels
        if not (is_channel or is_group or is_im):
            return result.get("channels")

        return channels

    except SlackApiError as e:
        logger.error(f"Error: {e}")
        raise e


def send_message(token: str, channel_id: str, message: str):
    """
    Sends a message to a channel

    Args:
        token (str): User's access token
        channel_id (str): The ID of the channel the user wishes to send a message to
        message (str): A simple message to be sent
    Returns:
        dict: A dictionary with success key, indicating the request was successful

    Raises:
        SlackApiError: Any error that occurs with the Slack API
    """
    client = WebClient(token=token)
    try:
        result = client.chat_postMessage(
            channel=channel_id,
            text=message,
            as_user=True
            # You could also use a blocks[] array to send richer content
        )
        # result includes information about the message (like TS)
        logger.info(f"The result is {result}")
        return {
            'success': True
        }

    except SlackApiError as e:
        logger.error(f"Error: {e}")
        raise e

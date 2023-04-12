"""SMSWithoutBorders Third-Party Platforms library Custom Exceptions"""


class PlatformDoesNotExist(Exception):
    """
    Exception raised when a platform is not found.

    Attributes:
        message (str): The message included in the exception.

    Methods:
        __init__(self, message="Platform Does Not Exist"): Initializes the PlatformDoesNotExist object with the given message.
        __str__(self): Returns a string representation of the exception with the error message.
    """

    def __init__(self, message="Platform Does Not Exist"):
        """
        Initializes the PlatformDoesNotExist object with the given message.

        Args:
            message (str): An optional message to include in the exception. Defaults to "Platform Does Not Exist".
        """
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        """
        Returns a string representation of the exception with the error message.

        Returns:
            str: The error message included in the exception.
        """
        return F"Error: {self.message}"

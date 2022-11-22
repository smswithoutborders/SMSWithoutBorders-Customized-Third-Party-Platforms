class PlatformDoesNotExist(Exception):
    """PlatformDoesNotExist()
    Exception raised when Platform is not Found
    """

    def __init__(self, message="Platform Does Not Exist"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return "Error: %s" % self.message
class MVAError(Exception):
    """Expected application error that can be returned safely to the client."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

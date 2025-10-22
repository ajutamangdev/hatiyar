"""Web server configuration with environment variable support."""

import os


class WebConfig:
    """Configuration for the pysecfw web server."""

    HOST: str = os.getenv("PYSECFW_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PYSECFW_PORT", "8000"))
    DEBUG: bool = os.getenv("PYSECFW_DEBUG", "false").lower() == "true"
    RELOAD: bool = os.getenv("PYSECFW_RELOAD", "false").lower() == "true"

    # CORS settings (for frontend development)
    CORS_ORIGINS: list = ["*"]

    @classmethod
    def get_host(cls) -> str:
        return cls.HOST

    @classmethod
    def get_port(cls) -> int:
        return cls.PORT


# Singleton instance
config = WebConfig()

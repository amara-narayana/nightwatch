"""
NIGHTWATCH — Lightweight Security Intelligence Platform
Main Startup Script
"""

import sys
import uvicorn
from app.core.config import get_settings


def main():
    settings = get_settings()
    print("=" * 70)
    print("  _   _ _____ _____ _   ___          __       _______ _____ _    _ ")
    print(" | \\ | |_   _/ ____| | | \\ \\        / / /\\   |__   __/ ____| |  | |")
    print(" |  \\| | | || |  __| |_| |\\ \\  /\\  / / /  \\     | | | |    | |__| |")
    print(" | . ` | | || | |_ |  _  | \\ \\/  \\/ / / /\\ \\    | | | |    |  __  |")
    print(" | |\\  |_| || |__| | | | |  \\  /\\  / / ____ \\   | | | |____| |  | |")
    print(" |_| \\_|_____\\_____|_| |_|   \\/  \\/ /_/    \\_\\  |_|  \\_____|_|  |_|")
    print("=" * 70)
    print(f" {settings.app_title} v{settings.version}")
    print(f" Listening on http://{settings.server.host}:{settings.server.port}")
    print("=" * 70)

    uvicorn.run(
        "app.api.main:app",
        host=settings.server.host,
        port=settings.server.port,
        log_level=settings.server.log_level,
        reload=False
    )


if __name__ == "__main__":
    main()

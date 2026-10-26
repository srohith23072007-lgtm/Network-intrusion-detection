import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env if present
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

class Settings:
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "alerts.db"))
    SURICATA_EVE_PATH: str = os.getenv("SURICATA_EVE_PATH", str(BASE_DIR / "logs" / "eve.json"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

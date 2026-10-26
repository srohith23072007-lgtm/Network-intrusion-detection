import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import Settings, BASE_DIR

db_raw_path = Settings.DATABASE_PATH
if os.path.isabs(db_raw_path):
    resolved_db_path = Path(db_raw_path)
else:
    resolved_db_path = (BASE_DIR / db_raw_path).resolve()

# Ensure target database directory exists
os.makedirs(resolved_db_path.parent, exist_ok=True)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{resolved_db_path.as_posix()}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

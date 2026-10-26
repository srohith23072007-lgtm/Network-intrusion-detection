from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from .database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(50), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    dest_ip = Column(String(50), nullable=True, index=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="TCP", nullable=True)
    signature = Column(String(255), nullable=True, index=True)
    category = Column(String(100), nullable=True)
    severity = Column(String(20), default="Medium", nullable=True, index=True)
    status = Column(String(30), default="open", nullable=True, index=True)
    description = Column(Text, nullable=True)
    raw_data = Column(Text, nullable=True)

    def __repr__(self):
        return f"<Alert id={self.id} sig={self.signature} sev={self.severity} status={self.status}>"

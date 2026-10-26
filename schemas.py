from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class AlertBase(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    signature: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = "Medium"
    status: Optional[str] = "open"
    description: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    description: Optional[str] = None

class AlertOut(AlertBase):
    id: int
    timestamp: datetime
    raw_data: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

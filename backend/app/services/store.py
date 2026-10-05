from collections import deque
from threading import Lock
from app.models.schemas import Incident, SecurityEventOut

EVENTS: deque[SecurityEventOut] = deque(maxlen=10000)
INCIDENTS: deque[Incident] = deque(maxlen=2000)
STORE_LOCK = Lock()

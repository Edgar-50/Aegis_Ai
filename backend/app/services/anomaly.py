from collections import deque
import numpy as np
from sklearn.ensemble import IsolationForest
from app.models.schemas import SecurityEventIn


class StreamingAnomalyDetector:
    def __init__(self, max_samples: int = 750, min_fit: int = 30):
        self.rows: deque[list[float]] = deque(maxlen=max_samples)
        self.min_fit = min_fit
        self.model = IsolationForest(
            n_estimators=120,
            contamination="auto",
            random_state=42,
        )

    @staticmethod
    def vectorize(event: SecurityEventIn) -> list[float]:
        return [
            float(event.failed_attempts),
            float(event.bytes_sent),
            float(event.bytes_received),
            float(event.destination_port or 0),
            1.0 if "fail" in event.event_type.lower() else 0.0,
            1.0 if event.process_name else 0.0,
        ]

    def score(self, event: SecurityEventIn) -> float:
        vector = self.vectorize(event)
        if len(self.rows) < self.min_fit:
            self.rows.append(vector)
            # Useful cold-start heuristic until the statistical baseline is large enough.
            magnitude = min(1.0, (
                event.failed_attempts / 20
                + event.bytes_sent / 150_000_000
                + (0.2 if (event.destination_port or 0) in {22, 23, 445, 3389, 5900} else 0)
            ))
            return round(max(0.0, magnitude), 3)

        matrix = np.asarray(self.rows, dtype=float)
        self.model.fit(matrix)
        raw = float(self.model.decision_function(np.asarray([vector], dtype=float))[0])
        anomaly = max(0.0, min(1.0, 0.5 - raw)) * 2
        self.rows.append(vector)
        return round(min(1.0, anomaly), 3)


ANOMALY_DETECTOR = StreamingAnomalyDetector()

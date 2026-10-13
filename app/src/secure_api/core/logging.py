"""Allowlisted JSON events: never format exceptions, payloads or SDK messages."""

import json
import logging
import sys
from datetime import UTC, datetime

ALLOWED_FIELDS = {"request_id", "endpoint", "status", "duration_ms", "event"}
logger = logging.getLogger("secure_api.audit")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        result = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
        }
        fields = getattr(record, "audit", {})
        result.update({name: value for name, value in fields.items() if name in ALLOWED_FIELDS})
        return json.dumps(result, ensure_ascii=True)


def configure_logging() -> None:
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    # Azure HTTP policies can log sensitive metadata; no SDK HTTP logging here.
    sdk_logger = logging.getLogger("azure")
    sdk_logger.handlers = [logging.NullHandler()]
    sdk_logger.propagate = False
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").disabled = True


def event(level: int, **fields: object) -> None:
    logger.log(level, "", extra={"audit": fields})

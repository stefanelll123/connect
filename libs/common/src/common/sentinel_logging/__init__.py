"""sentinel_logging package — structured JSON logging for sentinel nodes.

Quick start::

    from common.sentinel_logging import configure_logger, get_logger

    logger = configure_logger(service_id="my-svc", env="dev", role="producer")
    logger.log_request(event="request_decision", decision="permit", ...)
"""
from common.sentinel_logging.logger import SentinelLogger, configure_logger, get_logger
from common.sentinel_logging.ring_buffer import LogRingBuffer
from common.sentinel_logging.schema import SentinelLogEvent

__all__ = [
    "SentinelLogger",
    "configure_logger",
    "get_logger",
    "LogRingBuffer",
    "SentinelLogEvent",
]

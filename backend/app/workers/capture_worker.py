"""
Background capture worker module.

Provides a standalone worker that can run packet capture
in a separate process or as a background task.
"""

import time
import signal
import sys
from typing import Optional

from app.services.detector import DetectionEngine
from app.database.init_db import init_database
from app.core.config import settings
from app.core.logging import ids_logger


class CaptureWorker:
    """
    Background worker for packet capture and detection.

    Can be run as a standalone process or managed by the main application.
    Handles graceful shutdown on SIGINT/SIGTERM.
    """

    def __init__(self, detector: Optional[DetectionEngine] = None):
        """
        Initialize the capture worker.

        Args:
            detector: Detection engine instance (default: global)
        """
        self.detector = detector or DetectionEngine()
        self._running = False
        self._setup_signal_handlers()

        ids_logger.info("CaptureWorker initialized")

    def _setup_signal_handlers(self):
        """Setup handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully."""
        ids_logger.info(f"Received signal {signum}, initiating shutdown...")
        self.stop()
        sys.exit(0)

    def start(self):
        """
        Start the capture worker.

        Initializes database and starts detection engine.
        Blocks until stopped.
        """
        if self._running:
            ids_logger.warning("Worker already running")
            return

        ids_logger.info("Starting capture worker...")

        # Initialize database
        init_database()

        # Start detection
        success = self.detector.start_detection()
        if not success:
            ids_logger.error("Failed to start detection engine")
            return

        self._running = True
        ids_logger.info("Capture worker started")

        # Keep running until stopped
        try:
            while self._running:
                time.sleep(1)
                self._log_status_periodically()
        except KeyboardInterrupt:
            ids_logger.info("Keyboard interrupt received")
        finally:
            self.stop()

    def stop(self):
        """Stop the capture worker."""
        if not self._running:
            return

        ids_logger.info("Stopping capture worker...")
        self._running = False
        self.detector.stop_detection()
        ids_logger.info("Capture worker stopped")

    def _log_status_periodically(self):
        """Log status every minute."""
        status = self.detector.get_status()
        uptime = status["uptime_seconds"]

        # Log every 60 seconds
        if uptime > 0 and int(uptime) % 60 == 0:
            ids_logger.info(
                f"Worker status - Packets: {status['packets_processed']}, "
                f"Alerts: {status['alerts_generated']}, "
                f"Uptime: {int(uptime)}s"
            )


def run_worker():
    """
    Entry point for running the capture worker.

    Can be called directly or from a process manager.
    """
    ids_logger.info("=" * 50)
    ids_logger.info("IDS Capture Worker Starting")
    ids_logger.info(f"Interface: {settings.NETWORK_INTERFACE}")
    ids_logger.info(f"Filter: {settings.CAPTURE_FILTER}")
    ids_logger.info("=" * 50)

    worker = CaptureWorker()
    worker.start()


if __name__ == "__main__":
    # Allow running worker directly: python -m app.workers.capture_worker
    run_worker()

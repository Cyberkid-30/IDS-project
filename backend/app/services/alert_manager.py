"""
Alert manager service.

Handles alert creation, storage, aggregation, and statistics.
"""

from typing import Optional, Dict
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.models.alert import Alert
from app.models.signature import Signature
from app.core.enums import SeverityLevel, AlertStatus
from app.services.parser import ParsedPacket, PacketParser
from app.core.logging import ids_logger


class AlertManager:
    """
    Service for managing security alerts.

    Handles alert creation, deduplication, aggregation,
    and provides statistics and queries.
    """

    # Time window for alert aggregation (same signature + IPs)
    AGGREGATION_WINDOW_SECONDS = 60

    # Maximum payload snippet length to store
    MAX_SNIPPET_LENGTH = 500

    def __init__(self, parser: Optional[PacketParser] = None):
        """Initialize the alert manager."""
        self.parser = parser or PacketParser()
        ids_logger.debug("AlertManager initialized")

    def create_alert(
        self,
        db: Session,
        signature: Signature,
        packet: ParsedPacket,
        aggregate: bool = True,
    ) -> Alert:
        """
        Create a new alert or aggregate with existing.

        Args:
            db: Database session
            signature: Triggering signature
            packet: Matched packet
            aggregate: Whether to aggregate similar alerts

        Returns:
            Alert: Created or updated alert
        """
        # Check for existing recent alert to aggregate
        if aggregate:
            existing = self._find_aggregatable_alert(db, signature, packet)
            if existing:
                return self._aggregate_alert(db, existing)

        now = datetime.now(timezone.utc)

        # Create new alert
        payload_snippet = self.parser.get_payload_snippet(
            packet, self.MAX_SNIPPET_LENGTH
        )

        alert = Alert(
            signature_id=signature.id,
            source_ip=packet.source_ip,
            source_port=packet.source_port,
            dest_ip=packet.dest_ip,
            dest_port=packet.dest_port,
            protocol=packet.protocol,
            payload_snippet=payload_snippet,
            severity=signature.severity,
            status=AlertStatus.NEW,
            timestamp=now,
            packet_count=1,
            raw_packet=packet.raw_hex[:2000],  # Limit raw packet storage
        )

        db.add(alert)
        db.flush()  # Get the ID without committing

        ids_logger.info(
            f"Alert created: {signature.name} ({packet.source_ip} -> {packet.dest_ip})"
        )

        return alert

    def _find_aggregatable_alert(
        self, db: Session, signature: Signature, packet: ParsedPacket
    ) -> Optional[Alert]:
        """
        Find an existing alert that can be aggregated.

        Args:
            db: Database session
            signature: Triggering signature
            packet: Matched packet

        Returns:
            Alert: Existing alert to aggregate or None
        """
        window_start = datetime.now(timezone.utc) - timedelta(
            seconds=self.AGGREGATION_WINDOW_SECONDS
        )

        return (
            db.query(Alert)
            .filter(
                Alert.signature_id == signature.id,
                Alert.source_ip == packet.source_ip,
                Alert.dest_ip == packet.dest_ip,
                Alert.timestamp >= window_start,
                Alert.status == AlertStatus.NEW,
            )
            .first()
        )

    def _aggregate_alert(self, db: Session, alert: Alert) -> Alert:
        """
        Aggregate a new packet into an existing alert.

        Args:
            db: Database session
            alert: Existing alert to update

        Returns:
            Alert: Updated alert
        """
        alert.packet_count += 1  # type: ignore
        alert.timestamp = datetime.now(timezone.utc)  # type: ignore

        ids_logger.debug(
            f"Alert aggregated: ID {alert.id}, count now {alert.packet_count}"
        )

        return alert

    def get_alerts(
        self,
        db: Session,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> tuple:
        """
        Get filtered list of alerts with pagination.

        Args:
            db: Database session
            skip: Number of records to skip
            limit: Maximum records to return
            severity: Filter by severity level
            status: Filter by alert status
            source_ip: Filter by source IP
            dest_ip: Filter by destination IP
            start_date: Filter alerts after this date
            end_date: Filter alerts before this date

        Returns:
            tuple: (alerts list, total count)
        """
        query = db.query(Alert)

        # Apply filters
        if severity:
            query = query.filter(Alert.severity == severity)
        if status:
            query = query.filter(Alert.status == status)
        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)
        if dest_ip:
            query = query.filter(Alert.dest_ip == dest_ip)
        if start_date:
            query = query.filter(Alert.timestamp >= start_date)
        if end_date:
            query = query.filter(Alert.timestamp <= end_date)

        # Get total count
        total = query.count()

        # Get paginated results
        alerts = query.order_by(desc(Alert.timestamp)).offset(skip).limit(limit).all()

        return alerts, total

    def get_alert_by_id(self, db: Session, alert_id: str) -> Optional[Alert]:
        """
        Get a single alert by ID.

        Args:
            db: Database session
            alert_id: Alert ID

        Returns:
            Alert: Alert object or None
        """
        return db.query(Alert).filter(Alert.id == alert_id).first()

    def update_alert_status(
        self, db: Session, alert_id: str, status: AlertStatus
    ) -> Optional[Alert]:
        """
        Update an alert's status.

        Args:
            db: Database session
            alert_id: Alert ID
            status: New status value

        Returns:
            Alert: Updated alert or None if not found
        """
        alert = self.get_alert_by_id(db, alert_id)
        if alert:
            alert.status = status  # type: ignore
            db.flush()
            ids_logger.info(f"Alert {alert_id} status updated to {status.value}")
        return alert

    def delete_alert(self, db: Session, alert_id: str) -> bool:
        """
        Delete an alert.

        Args:
            db: Database session
            alert_id: Alert ID

        Returns:
            bool: True if deleted
        """
        alert = self.get_alert_by_id(db, alert_id)
        if alert:
            db.delete(alert)
            ids_logger.info(f"Alert {alert_id} deleted")
            return True
        return False

    def get_alert_stats(self, db: Session) -> Dict:
        """
        Get alert statistics.

        Args:
            db: Database session

        Returns:
            dict: Alert statistics
        """
        # Total alerts
        total = db.query(func.count(Alert.id)).scalar() or 0

        # Alerts by status
        new_alerts = (
            db.query(func.count(Alert.id))
            .filter(Alert.status == AlertStatus.NEW)
            .scalar()
            or 0
        )

        # Alerts by severity
        severity_counts = {}
        for severity in SeverityLevel:
            count = (
                db.query(func.count(Alert.id))
                .filter(Alert.severity == severity)
                .scalar()
                or 0
            )
            severity_counts[severity.value] = count

        # Alerts today
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        alerts_today = (
            db.query(func.count(Alert.id))
            .filter(Alert.timestamp >= today_start)
            .scalar()
            or 0
        )

        # Top source IPs
        top_sources = (
            db.query(Alert.source_ip, func.count(Alert.id).label("count"))
            .group_by(Alert.source_ip)
            .order_by(desc("count"))
            .limit(10)
            .all()
        )

        # Top triggered signatures
        top_sigs = (
            db.query(
                Alert.signature_id, Signature.name, func.count(Alert.id).label("count")
            )
            .join(Signature)
            .group_by(Alert.signature_id, Signature.name)
            .order_by(desc("count"))
            .limit(10)
            .all()
        )

        return {
            "total_alerts": total,
            "new_alerts": new_alerts,
            "critical_alerts": severity_counts.get("critical", 0),
            "high_alerts": severity_counts.get("high", 0),
            "medium_alerts": severity_counts.get("medium", 0),
            "low_alerts": severity_counts.get("low", 0),
            "alerts_today": alerts_today,
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_sources],
            "top_signatures": [
                {"id": sig_id, "name": name, "count": count}
                for sig_id, name, count in top_sigs
            ],
        }

    def cleanup_old_alerts(self, db: Session, days: int = 30) -> int:
        """
        Delete alerts older than specified days.

        Args:
            db: Database session
            days: Age threshold in days

        Returns:
            int: Number of alerts deleted
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        deleted = (
            db.query(Alert)
            .filter(Alert.timestamp < cutoff)
            .delete(synchronize_session=False)
        )

        ids_logger.info(f"Cleaned up {deleted} alerts older than {days} days")
        return deleted

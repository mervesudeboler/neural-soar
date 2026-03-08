"""
Sensor Aggregator - Combines data from multiple sensors
Calculates composite threat scores and maintains system state.
"""
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .log_sensor import LogEvent, LogSensor
from .network_sensor import NetworkAlert, NetworkSensor

logger = logging.getLogger(__name__)


@dataclass
class ThreatContext:
    """Represents the current threat context aggregated from all sensors."""
    timestamp: str
    threat_score: float  # 0-1
    severity_level: str  # low, medium, high, critical
    active_alerts_count: int
    failed_login_attempts: int
    ddos_detected: bool
    sql_injection_detected: bool
    port_scan_detected: bool
    brute_force_detected: bool
    suspicious_commands_detected: bool
    network_alerts: List[Dict[str, Any]] = field(default_factory=list)
    log_events: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class SensorAggregator:
    """
    Aggregates data from NetworkSensor and LogSensor.
    Calculates composite threat scores and updates system state.
    """

    def __init__(
        self,
        network_sensor: Optional[NetworkSensor] = None,
        log_sensor: Optional[LogSensor] = None,
        state_manager_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        aggregation_interval: float = 5.0,
    ):
        """
        Initialize SensorAggregator.

        Args:
            network_sensor: NetworkSensor instance.
            log_sensor: LogSensor instance.
            state_manager_callback: Callback to update SystemStateManager.
            aggregation_interval: Time between aggregations (seconds).
        """
        self.network_sensor = network_sensor or NetworkSensor()
        self.log_sensor = log_sensor or LogSensor()
        self.state_manager_callback = state_manager_callback
        self.aggregation_interval = aggregation_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Current threat context
        self._current_context: Optional[ThreatContext] = None

        # Alert history (rolling window)
        self._recent_alerts: List[NetworkAlert] = []
        self._recent_events: List[LogEvent] = []
        self._max_history = 100

        # Thresholds for threat detection
        self._ddos_threshold = 10  # Number of alerts in short timeframe
        self._brute_force_threshold = 5  # Failed login attempts
        self._port_scan_threshold = 3  # Number of port scan alerts

        logger.info("SensorAggregator initialized")

    def start(self) -> None:
        """Start the aggregator in a background thread."""
        with self._lock:
            if self._running:
                logger.warning("SensorAggregator is already running")
                return

            # Start sensors
            self.network_sensor.start()
            self.log_sensor.start()

            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            logger.info("SensorAggregator started")

    def stop(self) -> None:
        """Stop the aggregator."""
        with self._lock:
            self._running = False

        # Stop sensors
        self.network_sensor.stop()
        self.log_sensor.stop()

        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

        logger.info("SensorAggregator stopped")

    def _run_loop(self) -> None:
        """Main aggregation loop running in background thread."""
        try:
            while self._running:
                try:
                    self._perform_aggregation()
                    time.sleep(self.aggregation_interval)
                except Exception as e:
                    logger.error(f"Error in aggregation loop: {e}")
                    time.sleep(self.aggregation_interval)

        except Exception as e:
            logger.error(f"Fatal error in SensorAggregator: {e}")
            with self._lock:
                self._running = False

    def _perform_aggregation(self) -> None:
        """Perform threat aggregation and context calculation."""
        with self._lock:
            # Get latest statistics from sensors
            network_stats = self.network_sensor.get_statistics()
            log_stats = self.log_sensor.get_statistics()

            # Calculate threat components
            network_threat_score = self._calculate_network_threat_score(network_stats)
            auth_threat_score = self._calculate_auth_threat_score(log_stats)

            # Detect specific threats
            ddos_detected = self._detect_ddos(network_stats)
            sql_injection_detected = self._detect_sql_injection(network_stats)
            port_scan_detected = self._detect_port_scan(network_stats)
            brute_force_detected = self._detect_brute_force(log_stats)
            suspicious_commands = self._detect_suspicious_commands(log_stats)

            # Calculate composite threat score
            composite_score = (network_threat_score * 0.6) + (auth_threat_score * 0.4)
            composite_score = min(1.0, max(0.0, composite_score))

            # Determine severity level
            if composite_score >= 0.8:
                severity_level = "critical"
            elif composite_score >= 0.6:
                severity_level = "high"
            elif composite_score >= 0.4:
                severity_level = "medium"
            else:
                severity_level = "low"

            # Generate recommendations
            recommendations = self._generate_recommendations(
                ddos_detected,
                sql_injection_detected,
                port_scan_detected,
                brute_force_detected,
                suspicious_commands,
            )

            # Create threat context
            context = ThreatContext(
                timestamp=datetime.now().isoformat(),
                threat_score=composite_score,
                severity_level=severity_level,
                active_alerts_count=network_stats.get("total_alerts", 0),
                failed_login_attempts=log_stats.get("failed_login_count", 0),
                ddos_detected=ddos_detected,
                sql_injection_detected=sql_injection_detected,
                port_scan_detected=port_scan_detected,
                brute_force_detected=brute_force_detected,
                suspicious_commands_detected=suspicious_commands,
                recommendations=recommendations,
            )

            self._current_context = context

            # Notify state manager
            if self.state_manager_callback:
                try:
                    self.state_manager_callback(context.to_dict())
                except Exception as e:
                    logger.error(f"Error calling state manager callback: {e}")

    def _calculate_network_threat_score(self, network_stats: Dict[str, Any]) -> float:
        """
        Calculate threat score from network sensor data.

        Args:
            network_stats: Network sensor statistics.

        Returns:
            Threat score (0-1).
        """
        score = 0.0

        # Severity-weighted alert count
        alerts_by_severity = network_stats.get("alerts_by_severity", {})
        high_severity = alerts_by_severity.get(3, 0)
        medium_severity = alerts_by_severity.get(2, 0)
        low_severity = alerts_by_severity.get(1, 0)

        # Weight high severity alerts more
        weighted_alerts = (high_severity * 0.5) + (medium_severity * 0.2) + (
            low_severity * 0.05
        )

        # Normalize to 0-1 (assuming 20 weighted alerts = maximum threat)
        score = min(1.0, weighted_alerts / 20.0)

        # Category-based threat boost
        alerts_by_category = network_stats.get("alerts_by_category", {})

        if alerts_by_category.get("ddos", 0) > 0:
            score = min(1.0, score + 0.3)

        if alerts_by_category.get("sql_injection", 0) > 0:
            score = min(1.0, score + 0.2)

        if alerts_by_category.get("port_scan", 0) > 2:
            score = min(1.0, score + 0.15)

        return min(1.0, max(0.0, score))

    def _calculate_auth_threat_score(self, log_stats: Dict[str, Any]) -> float:
        """
        Calculate threat score from authentication/log data.

        Args:
            log_stats: Log sensor statistics.

        Returns:
            Threat score (0-1).
        """
        score = 0.0

        failed_logins = log_stats.get("failed_login_count", 0)
        suspicious_commands = log_stats.get("suspicious_commands_count", 0)
        auth_failure_rate = log_stats.get("auth_failure_rate", 0.0)

        # Failed login threat (assuming 10+ failed attempts is high threat)
        score += min(1.0, failed_logins / 10.0) * 0.5

        # Suspicious commands threat
        score += min(1.0, suspicious_commands / 5.0) * 0.3

        # Auth failure rate
        if auth_failure_rate > 0.5:
            score += 0.2

        return min(1.0, max(0.0, score))

    def _detect_ddos(self, network_stats: Dict[str, Any]) -> bool:
        """Detect DDoS attack."""
        alerts_by_category = network_stats.get("alerts_by_category", {})
        ddos_alerts = alerts_by_category.get("ddos", 0)
        return ddos_alerts >= self._ddos_threshold

    def _detect_sql_injection(self, network_stats: Dict[str, Any]) -> bool:
        """Detect SQL injection attempt."""
        alerts_by_category = network_stats.get("alerts_by_category", {})
        sql_alerts = alerts_by_category.get("sql_injection", 0)
        return sql_alerts > 0

    def _detect_port_scan(self, network_stats: Dict[str, Any]) -> bool:
        """Detect port scan."""
        alerts_by_category = network_stats.get("alerts_by_category", {})
        port_scan_alerts = alerts_by_category.get("port_scan", 0)
        return port_scan_alerts >= self._port_scan_threshold

    def _detect_brute_force(self, log_stats: Dict[str, Any]) -> bool:
        """Detect brute force attack."""
        failed_logins = log_stats.get("failed_login_count", 0)
        return failed_logins >= self._brute_force_threshold

    def _detect_suspicious_commands(self, log_stats: Dict[str, Any]) -> bool:
        """Detect suspicious command execution."""
        suspicious_commands = log_stats.get("suspicious_commands_count", 0)
        return suspicious_commands > 0

    def _generate_recommendations(
        self,
        ddos_detected: bool,
        sql_injection_detected: bool,
        port_scan_detected: bool,
        brute_force_detected: bool,
        suspicious_commands: bool,
    ) -> List[str]:
        """
        Generate security recommendations based on detected threats.

        Args:
            ddos_detected: DDoS attack detected.
            sql_injection_detected: SQL injection detected.
            port_scan_detected: Port scan detected.
            brute_force_detected: Brute force detected.
            suspicious_commands: Suspicious commands detected.

        Returns:
            List of recommendations.
        """
        recommendations = []

        if ddos_detected:
            recommendations.append(
                "DDoS detected: Enable rate limiting and consider activating DDoS mitigation rules"
            )
            recommendations.append(
                "DDoS detected: Contact ISP if attack traffic is overwhelming"
            )

        if sql_injection_detected:
            recommendations.append(
                "SQL injection detected: Review and patch database input validation"
            )
            recommendations.append(
                "SQL injection detected: Update WAF rules to block injection patterns"
            )

        if port_scan_detected:
            recommendations.append(
                "Port scan detected: Harden firewall rules and hide banner information"
            )
            recommendations.append(
                "Port scan detected: Monitor for follow-up attacks on open ports"
            )

        if brute_force_detected:
            recommendations.append(
                "Brute force detected: Enable account lockout after failed attempts"
            )
            recommendations.append(
                "Brute force detected: Deploy multi-factor authentication"
            )
            recommendations.append("Brute force detected: Review SSH configuration")

        if suspicious_commands:
            recommendations.append(
                "Suspicious commands detected: Audit recent user activity and sudo logs"
            )
            recommendations.append(
                "Suspicious commands detected: Review file integrity and system changes"
            )

        return recommendations

    def get_current_threat_context(self) -> Optional[Dict[str, Any]]:
        """
        Get the current threat context.

        Returns:
            Threat context dictionary or None if not available.
        """
        with self._lock:
            if self._current_context:
                return self._current_context.to_dict()
            return None

    def register_network_alert_callback(
        self, callback: Callable[[NetworkAlert], None]
    ) -> None:
        """
        Register a callback for network alerts.

        Args:
            callback: Function to call when network alert is received.
        """
        self.network_sensor.alert_callback = callback

    def register_log_event_callback(
        self, callback: Callable[[LogEvent], None]
    ) -> None:
        """
        Register a callback for log events.

        Args:
            callback: Function to call when log event is received.
        """
        self.log_sensor.event_callback = callback

    def get_sensor_statistics(self) -> Dict[str, Any]:
        """
        Get statistics from all sensors.

        Returns:
            Dictionary containing network and log sensor statistics.
        """
        return {
            "network_sensor": self.network_sensor.get_statistics(),
            "log_sensor": self.log_sensor.get_statistics(),
            "threat_context": self.get_current_threat_context(),
        }

    def reset_sensors(self) -> None:
        """Reset all sensor statistics."""
        self.network_sensor.reset_statistics()
        self.log_sensor.reset_statistics()
        logger.info("All sensor statistics reset")

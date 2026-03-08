"""
Network Sensor - Collects IDS alerts from Suricata/Snort
Monitors network traffic and generates security alerts.
"""
import json
import logging
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkAlert:
    """Represents a network security alert from IDS."""
    alert_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    severity: int  # 1-3 (1=low, 2=medium, 3=high)
    category: str  # port_scan, brute_force, ddos, sql_injection, normal
    signature: str
    payload_size: int
    connection_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return asdict(self)


class NetworkSensor:
    """
    Monitors network traffic through IDS alerts.
    Can operate in simulation mode (generates synthetic alerts) or real mode
    (reads from Suricata EVE JSON log file).
    """

    def __init__(
        self,
        simulation_mode: bool = True,
        eve_log_path: str = "/var/log/suricata/eve.json",
        alert_callback: Optional[Callable[[NetworkAlert], None]] = None,
        check_interval: float = 2.0,
    ):
        """
        Initialize NetworkSensor.

        Args:
            simulation_mode: If True, generates synthetic alerts. If False, reads eve.json.
            eve_log_path: Path to Suricata EVE JSON log file.
            alert_callback: Callback function called for each new alert.
            check_interval: Time between alert checks (seconds).
        """
        self.simulation_mode = simulation_mode
        self.eve_log_path = Path(eve_log_path)
        self.alert_callback = alert_callback
        self.check_interval = check_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Statistics
        self.total_alerts = 0
        self.alerts_by_category: Dict[str, int] = {
            "port_scan": 0,
            "brute_force": 0,
            "ddos": 0,
            "sql_injection": 0,
            "normal": 0,
        }
        self.alerts_by_severity: Dict[int, int] = {1: 0, 2: 0, 3: 0}

        # For real mode: track file position
        self._file_position = 0
        self._last_file_check = 0.0

        logger.info(f"NetworkSensor initialized (simulation_mode={simulation_mode})")

    def start(self) -> None:
        """Start the sensor in a background thread."""
        with self._lock:
            if self._running:
                logger.warning("NetworkSensor is already running")
                return

            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            logger.info("NetworkSensor started")

    def stop(self) -> None:
        """Stop the sensor."""
        with self._lock:
            self._running = False

        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

        logger.info("NetworkSensor stopped")

    def _run_loop(self) -> None:
        """Main sensor loop running in background thread."""
        try:
            while self._running:
                try:
                    if self.simulation_mode:
                        self._process_simulation()
                    else:
                        self._process_eve_log()

                    time.sleep(self.check_interval)
                except Exception as e:
                    logger.error(f"Error in NetworkSensor loop: {e}")
                    time.sleep(self.check_interval)

        except Exception as e:
            logger.error(f"Fatal error in NetworkSensor: {e}")
            with self._lock:
                self._running = False

    def _process_simulation(self) -> None:
        """Generate and process simulated alerts."""
        # Randomly decide whether to generate an alert this cycle
        if random.random() < 0.4:  # 40% chance per cycle
            alert = self._simulate_alert()
            self._record_alert(alert)
            if self.alert_callback:
                self.alert_callback(alert)

    def _process_eve_log(self) -> None:
        """Read new alerts from Suricata EVE JSON log file."""
        try:
            if not self.eve_log_path.exists():
                logger.debug(f"EVE log file not found: {self.eve_log_path}")
                return

            with open(self.eve_log_path, "r") as f:
                # Seek to last known position
                f.seek(self._file_position)

                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)

                        # Parse EVE JSON alert
                        if "alert" in data:
                            alert = self._parse_eve_alert(data)
                            if alert:
                                self._record_alert(alert)
                                if self.alert_callback:
                                    self.alert_callback(alert)
                    except json.JSONDecodeError:
                        logger.debug(f"Failed to parse JSON line: {line[:100]}")

                # Update file position
                self._file_position = f.tell()

        except Exception as e:
            logger.error(f"Error reading EVE log: {e}")

    def _simulate_alert(self) -> NetworkAlert:
        """Generate a realistic simulated network alert."""
        # Common attack signatures
        signatures = {
            "port_scan": [
                "Nmap Scan - SYN",
                "TCP SYN Scan",
                "Port Sweep",
                "Horizontal Port Scan",
            ],
            "brute_force": [
                "SSH Brute Force",
                "HTTP Basic Auth Brute Force",
                "FTP Brute Force",
                "RDP Brute Force",
            ],
            "ddos": [
                "DDoS - UDP Flood",
                "DDoS - SYN Flood",
                "DDoS - HTTP Flood",
                "Slow HTTP Attack",
            ],
            "sql_injection": [
                "SQL Injection - Union Select",
                "SQL Injection - Boolean Blind",
                "SQL Injection - Time-Based",
                "SQL Injection - Stacked Queries",
            ],
            "normal": [
                "HTTP GET Request",
                "HTTPS Connection",
                "DNS Query",
                "NTP Response",
            ],
        }

        # Weighted distribution for alert categories
        category_weights = {
            "normal": 0.50,
            "port_scan": 0.15,
            "brute_force": 0.20,
            "ddos": 0.10,
            "sql_injection": 0.05,
        }

        category = random.choices(
            list(category_weights.keys()),
            weights=list(category_weights.values()),
        )[0]

        # Severity mapping
        severity_by_category = {
            "normal": 1,
            "port_scan": 2,
            "brute_force": 2,
            "ddos": 3,
            "sql_injection": 3,
        }
        severity = severity_by_category.get(category, 1)

        # Add some randomness to severity
        if random.random() < 0.2:
            severity = min(3, severity + 1)

        signature = random.choice(signatures[category])

        # Generate IPs
        src_ip = self._generate_random_ip()
        dst_ip = self._generate_random_ip()

        # Generate ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([22, 23, 80, 443, 3306, 3389, 5432])

        protocol = random.choice(["TCP", "UDP"])

        # Payload size varies by category
        if category == "ddos":
            payload_size = random.randint(50, 1500)
        elif category == "sql_injection":
            payload_size = random.randint(100, 500)
        else:
            payload_size = random.randint(20, 300)

        # Connection count (especially relevant for brute force)
        if category == "brute_force":
            connection_count = random.randint(10, 100)
        elif category == "ddos":
            connection_count = random.randint(100, 1000)
        else:
            connection_count = random.randint(1, 5)

        alert_id = f"alert_{int(time.time() * 1000)}_{random.randint(0, 9999)}"
        timestamp = datetime.now().isoformat()

        alert = NetworkAlert(
            alert_id=alert_id,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            severity=severity,
            category=category,
            signature=signature,
            payload_size=payload_size,
            connection_count=connection_count,
            metadata={
                "event_type": "network_alert",
                "source": "simulated_ids",
            },
        )

        return alert

    def _parse_eve_alert(self, eve_data: Dict[str, Any]) -> Optional[NetworkAlert]:
        """
        Parse a Suricata EVE JSON alert into a NetworkAlert.

        Args:
            eve_data: Raw EVE JSON event data.

        Returns:
            NetworkAlert or None if parsing failed.
        """
        try:
            alert_data = eve_data.get("alert", {})
            src = eve_data.get("src_ip", "0.0.0.0")
            dst = eve_data.get("dest_ip", "0.0.0.0")

            timestamp = eve_data.get("timestamp", datetime.now().isoformat())
            protocol = eve_data.get("proto", "TCP").upper()
            signature = alert_data.get("signature", "Unknown")
            severity = alert_data.get("severity", 1)

            # Extract ports
            src_port = eve_data.get("src_port", 0)
            dst_port = eve_data.get("dest_port", 0)

            # Determine category from signature
            category = self._categorize_signature(signature)

            # Payload size estimation
            payload_size = eve_data.get("payload", {})
            if isinstance(payload_size, dict):
                payload_size = len(json.dumps(payload_size))
            else:
                payload_size = len(str(payload_size)) if payload_size else 0

            alert_id = f"alert_{int(time.time() * 1000)}_{random.randint(0, 9999)}"

            alert = NetworkAlert(
                alert_id=alert_id,
                timestamp=timestamp,
                src_ip=src,
                dst_ip=dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                severity=severity,
                category=category,
                signature=signature,
                payload_size=payload_size,
                connection_count=1,
                metadata={"event_type": "network_alert", "source": "suricata_eve"},
            )

            return alert

        except Exception as e:
            logger.debug(f"Failed to parse EVE alert: {e}")
            return None

    def _categorize_signature(self, signature: str) -> str:
        """Categorize alert based on signature name."""
        signature_lower = signature.lower()

        if any(x in signature_lower for x in ["port scan", "port sweep", "nmap"]):
            return "port_scan"
        elif any(x in signature_lower for x in ["brute force", "ssh", "auth"]):
            return "brute_force"
        elif any(x in signature_lower for x in ["ddos", "flood", "syn", "udp"]):
            return "ddos"
        elif any(x in signature_lower for x in ["sql injection", "sql"]):
            return "sql_injection"
        else:
            return "normal"

    def _generate_random_ip(self) -> str:
        """Generate a random IP address."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

    def _record_alert(self, alert: NetworkAlert) -> None:
        """Record alert statistics."""
        with self._lock:
            self.total_alerts += 1
            self.alerts_by_category[alert.category] = (
                self.alerts_by_category.get(alert.category, 0) + 1
            )
            self.alerts_by_severity[alert.severity] = (
                self.alerts_by_severity.get(alert.severity, 0) + 1
            )

    def get_statistics(self) -> Dict[str, Any]:
        """Get sensor statistics."""
        with self._lock:
            return {
                "total_alerts": self.total_alerts,
                "alerts_by_category": dict(self.alerts_by_category),
                "alerts_by_severity": dict(self.alerts_by_severity),
            }

    def reset_statistics(self) -> None:
        """Reset sensor statistics."""
        with self._lock:
            self.total_alerts = 0
            self.alerts_by_category = {
                "port_scan": 0,
                "brute_force": 0,
                "ddos": 0,
                "sql_injection": 0,
                "normal": 0,
            }
            self.alerts_by_severity = {1: 0, 2: 0, 3: 0}

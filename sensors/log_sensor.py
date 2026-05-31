"""
Log Sensor - Collects authentication and system events from logs
Monitors authentication attempts, privilege escalation, and system changes.
"""
import logging
import random
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class LogEvent:
    """Represents a parsed system log event."""
    event_id: str
    timestamp: str
    source: str  # auth.log, syslog, etc.
    event_type: str  # failed_login, sudo, user_creation, firewall, service, etc.
    severity: int  # 1-3 (1=low, 2=medium, 3=high)
    username: Optional[str] = None
    hostname: Optional[str] = None
    message: str = ""
    raw_line: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return asdict(self)


class LogSensor:
    """
    Monitors system and authentication logs.
    Can operate in simulation mode (generates synthetic events) or real mode
    (reads from actual log files).
    """

    def __init__(
        self,
        simulation_mode: bool = True,
        auth_log_path: str = "/var/log/auth.log",
        syslog_path: str = "/var/log/syslog",
        event_callback: Optional[Callable[[LogEvent], None]] = None,
        check_interval: float = 1.0,
    ):
        """
        Initialize LogSensor.

        Args:
            simulation_mode: If True, generates synthetic events. If False, reads actual logs.
            auth_log_path: Path to authentication log file.
            syslog_path: Path to system log file.
            event_callback: Callback function called for each new event.
            check_interval: Time between log checks (seconds).
        """
        self.simulation_mode = simulation_mode
        self.auth_log_path = Path(auth_log_path)
        self.syslog_path = Path(syslog_path)
        self.event_callback = event_callback
        self.check_interval = check_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Statistics
        self.failed_login_count = 0
        self.suspicious_commands_count = 0
        self.auth_failure_rate = 0.0
        self.total_events = 0

        # For real mode: track file positions
        self._auth_log_position = 0
        self._syslog_position = 0

        # Common usernames for simulation
        self.common_usernames = [
            "root",
            "admin",
            "user",
            "ubuntu",
            "centos",
            "oracle",
            "postgres",
            "mysql",
        ]

        # Suspicious commands for simulation
        self.suspicious_commands = [
            "cat /etc/shadow",
            "chmod 777",
            "wget malicious.com",
            "curl | bash",
            "nc -l -p",
            "dd if=/dev/zero",
            "fork() && fork()",
        ]

        logger.info(f"LogSensor initialized (simulation_mode={simulation_mode})")

    def start(self) -> None:
        """Start the sensor in a background thread."""
        with self._lock:
            if self._running:
                logger.warning("LogSensor is already running")
                return

            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            logger.info("LogSensor started")

    def stop(self) -> None:
        """Stop the sensor."""
        with self._lock:
            self._running = False

        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

        logger.info("LogSensor stopped")

    def _run_loop(self) -> None:
        """Main sensor loop running in background thread."""
        try:
            while self._running:
                try:
                    if self.simulation_mode:
                        self._process_simulation()
                    else:
                        self._process_log_files()

                    time.sleep(self.check_interval)
                except Exception as e:
                    logger.error(f"Error in LogSensor loop: {e}")
                    time.sleep(self.check_interval)

        except Exception as e:
            logger.error(f"Fatal error in LogSensor: {e}")
            with self._lock:
                self._running = False

    def _process_simulation(self) -> None:
        """Generate and process simulated log events."""
        # Randomly decide whether to generate events this cycle
        if random.random() < 0.3:  # 30% chance per cycle

            # Generate different types of events with weighted distribution
            event_types_weights = {
                "failed_login": 0.40,
                "sudo": 0.20,
                "user_creation": 0.10,
                "firewall": 0.15,
                "service": 0.15,
            }

            event_type = random.choices(
                list(event_types_weights.keys()),
                weights=list(event_types_weights.values()),
            )[0]

            event = self._simulate_event(event_type)
            self._record_event(event)
            if self.event_callback:
                self.event_callback(event)

    def _process_log_files(self) -> None:
        """Read new events from auth.log and syslog files."""
        self._process_auth_log()
        self._process_syslog()

    def _process_auth_log(self) -> None:
        """Process auth.log file."""
        try:
            if not self.auth_log_path.exists():
                logger.debug(f"Auth log file not found: {self.auth_log_path}")
                return

            with open(self.auth_log_path, "r") as f:
                f.seek(self._auth_log_position)

                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    event = self._parse_auth_log_line(line)
                    if event:
                        self._record_event(event)
                        if self.event_callback:
                            self.event_callback(event)

                self._auth_log_position = f.tell()

        except Exception as e:
            logger.error(f"Error reading auth.log: {e}")

    def _process_syslog(self) -> None:
        """Process syslog file."""
        try:
            if not self.syslog_path.exists():
                logger.debug(f"Syslog file not found: {self.syslog_path}")
                return

            with open(self.syslog_path, "r") as f:
                f.seek(self._syslog_position)

                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    event = self._parse_syslog_line(line)
                    if event:
                        self._record_event(event)
                        if self.event_callback:
                            self.event_callback(event)

                self._syslog_position = f.tell()

        except Exception as e:
            logger.error(f"Error reading syslog: {e}")

    def _simulate_event(self, event_type: str) -> LogEvent:
        """Generate a simulated log event."""
        timestamp = datetime.now().isoformat()
        username = random.choice(self.common_usernames)
        hostname = f"server{random.randint(1, 10)}"
        event_id = f"log_{int(time.time() * 1000)}_{random.randint(0, 9999)}"

        severity = 1
        message = ""
        raw_line = ""

        if event_type == "failed_login":
            severity = 2
            f"pass{random.randint(100, 999)}"
            source_ip = self._generate_random_ip()
            message = f"Failed password for {username} from {source_ip} port {random.randint(40000, 60000)} ssh2"
            raw_line = f"{datetime.now().strftime('%b %d %H:%M:%S')} {hostname} sshd[{random.randint(1000, 9999)}]: {message}"

        elif event_type == "sudo":
            severity = 2
            command = random.choice(self.suspicious_commands)
            message = f"sudo: {username} : TTY=pts/{random.randint(0, 5)} ; PWD=/home/{username} ; USER=root ; COMMAND={command}"
            raw_line = f"{datetime.now().strftime('%b %d %H:%M:%S')} {hostname} sudo: {message}"

        elif event_type == "user_creation":
            severity = 2
            new_user = f"user{random.randint(100, 999)}"
            message = f"New user created: {new_user}"
            raw_line = f"{datetime.now().strftime('%b %d %H:%M:%S')} {hostname} useradd[{random.randint(1000, 9999)}]: {message}"

        elif event_type == "firewall":
            severity = 1
            action = random.choice(["REJECT", "DROP", "ACCEPT"])
            src_ip = self._generate_random_ip()
            dst_ip = self._generate_random_ip()
            message = f"UFW {action} IN=eth0 OUT= MAC={':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])} SRC={src_ip} DST={dst_ip}"
            raw_line = f"{datetime.now().strftime('%b %d %H:%M:%S')} {hostname} kernel: {message}"

        elif event_type == "service":
            severity = 1
            service = random.choice(["ssh", "apache2", "nginx", "mysql", "postgresql"])
            action = random.choice(["started", "stopped", "restarted"])
            message = f"Service {service} {action}"
            raw_line = f"{datetime.now().strftime('%b %d %H:%M:%S')} {hostname} systemd[1]: {message}"

        event = LogEvent(
            event_id=event_id,
            timestamp=timestamp,
            source="simulated_logs",
            event_type=event_type,
            severity=severity,
            username=username,
            hostname=hostname,
            message=message,
            raw_line=raw_line,
            metadata={"source": "simulated_logs"},
        )

        return event

    def _parse_auth_log_line(self, line: str) -> Optional[LogEvent]:
        """
        Parse a line from auth.log.

        Args:
            line: Raw log line.

        Returns:
            LogEvent or None if parsing failed.
        """
        try:
            timestamp = datetime.now().isoformat()
            event_id = f"log_{int(time.time() * 1000)}_{random.randint(0, 9999)}"

            # Failed password attempt
            if "Failed password" in line:
                match = re.search(r"Failed password for (\w+) from ([\d.]+)", line)
                username = match.group(1) if match else "unknown"
                severity = 2

                event = LogEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    source="auth.log",
                    event_type="failed_login",
                    severity=severity,
                    username=username,
                    message=line,
                    raw_line=line,
                    metadata={"source": "auth.log", "log_type": "ssh"},
                )
                return event

            # Invalid user attempt
            elif "Invalid user" in line:
                match = re.search(r"Invalid user (\w+) from ([\d.]+)", line)
                username = match.group(1) if match else "unknown"
                severity = 2

                event = LogEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    source="auth.log",
                    event_type="failed_login",
                    severity=severity,
                    username=username,
                    message=line,
                    raw_line=line,
                    metadata={"source": "auth.log", "log_type": "ssh"},
                )
                return event

            # Sudo usage
            elif "sudo:" in line and "COMMAND=" in line:
                match = re.search(r"sudo: (\w+)", line)
                username = match.group(1) if match else "unknown"
                severity = 2

                event = LogEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    source="auth.log",
                    event_type="sudo",
                    severity=severity,
                    username=username,
                    message=line,
                    raw_line=line,
                    metadata={"source": "auth.log", "log_type": "sudo"},
                )
                return event

            # User created
            elif "useradd" in line and "created" in line:
                match = re.search(r"user (\w+) created", line)
                username = match.group(1) if match else "unknown"
                severity = 2

                event = LogEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    source="auth.log",
                    event_type="user_creation",
                    severity=severity,
                    username=username,
                    message=line,
                    raw_line=line,
                    metadata={"source": "auth.log"},
                )
                return event

            return None

        except Exception as e:
            logger.debug(f"Failed to parse auth.log line: {e}")
            return None

    def _parse_syslog_line(self, line: str) -> Optional[LogEvent]:
        """
        Parse a line from syslog.

        Args:
            line: Raw log line.

        Returns:
            LogEvent or None if parsing failed.
        """
        try:
            timestamp = datetime.now().isoformat()
            event_id = f"log_{int(time.time() * 1000)}_{random.randint(0, 9999)}"

            # Firewall rule changes
            if "UFW" in line or "kernel:" in line:
                severity = 1
                event = LogEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    source="syslog",
                    event_type="firewall",
                    severity=severity,
                    message=line,
                    raw_line=line,
                    metadata={"source": "syslog", "log_type": "firewall"},
                )
                return event

            # Service state changes
            elif "systemd[1]:" in line and any(
                x in line for x in ["started", "stopped", "restarted"]
            ):
                severity = 1
                match = re.search(r"(\w+[\w\-]*) (started|stopped|restarted)", line)
                service = match.group(1) if match else "unknown"

                event = LogEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    source="syslog",
                    event_type="service",
                    severity=severity,
                    message=f"Service {service} state changed",
                    raw_line=line,
                    metadata={"source": "syslog", "log_type": "service"},
                )
                return event

            return None

        except Exception as e:
            logger.debug(f"Failed to parse syslog line: {e}")
            return None

    def _generate_random_ip(self) -> str:
        """Generate a random IP address."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

    def _record_event(self, event: LogEvent) -> None:
        """Record event statistics."""
        with self._lock:
            self.total_events += 1

            if event.event_type == "failed_login":
                self.failed_login_count += 1
            elif event.event_type == "sudo":
                self.suspicious_commands_count += 1

            # Calculate failure rate (failed logins / total events)
            if self.total_events > 0:
                self.auth_failure_rate = self.failed_login_count / self.total_events

    def get_statistics(self) -> Dict[str, Any]:
        """Get sensor statistics."""
        with self._lock:
            return {
                "total_events": self.total_events,
                "failed_login_count": self.failed_login_count,
                "suspicious_commands_count": self.suspicious_commands_count,
                "auth_failure_rate": self.auth_failure_rate,
            }

    def reset_statistics(self) -> None:
        """Reset sensor statistics."""
        with self._lock:
            self.failed_login_count = 0
            self.suspicious_commands_count = 0
            self.auth_failure_rate = 0.0
            self.total_events = 0

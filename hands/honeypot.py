"""
Honeypot Manager - Creates and manages honeypot instances.
Simulates attacker interactions and captures intelligence.
"""
import logging
import random
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any


@dataclass
class HoneypotInstance:
    """Represents a honeypot instance."""
    id: str
    target_ip: str
    honeypot_ip: str
    service_type: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    captured_data: List[str] = field(default_factory=list)
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "target_ip": self.target_ip,
            "honeypot_ip": self.honeypot_ip,
            "service_type": self.service_type,
            "created_at": self.created_at.isoformat(),
            "captured_data": self.captured_data,
            "active": self.active,
        }


class HoneypotManager:
    """
    Manages honeypot instances for capturing attacker intelligence.
    In simulation mode: generates realistic fake captured data.
    In production mode: manages actual Docker containers or Kubernetes pods.
    """

    def __init__(self, simulation_mode: bool = True):
        """
        Initialize the honeypot manager.

        Args:
            simulation_mode: Whether to run in simulation mode
        """
        self.simulation_mode = simulation_mode
        self.honeypots: Dict[str, HoneypotInstance] = {}
        self.redirections: Dict[str, str] = {}  # src_ip -> honeypot_id

        self.logger = logging.getLogger(__name__)

        # Fake attacker behavior templates for simulation
        self.ssh_commands = [
            "ls -la",
            "cat /etc/passwd",
            "whoami",
            "id",
            "uname -a",
            "ps aux",
            "netstat -an",
            "ifconfig",
            "find / -name '*.key' 2>/dev/null",
            "find / -name '*.sh' 2>/dev/null",
        ]

        self.ssh_credentials = [
            ("root", "password"),
            ("admin", "admin"),
            ("ubuntu", "ubuntu"),
            ("user", "12345"),
            ("postgres", "postgres"),
            ("mysql", "mysql"),
        ]

        self.http_payloads = [
            "GET / HTTP/1.1",
            "GET /admin HTTP/1.1",
            "GET /api HTTP/1.1",
            "POST /login HTTP/1.1",
            "SELECT * FROM users WHERE 1=1",
            "' OR '1'='1",
            "../../../etc/passwd",
            "../../admin.php",
        ]

    def create_honeypot(
        self, target_ip: str, service_type: str = "ssh"
    ) -> HoneypotInstance:
        """
        Create a new honeypot instance.

        Args:
            target_ip: The attacker's IP address
            service_type: Type of service to emulate (ssh, http, ftp, etc.)

        Returns:
            HoneypotInstance object
        """
        try:
            honeypot_id = str(uuid.uuid4())[:8]
            honeypot_ip = self._generate_honeypot_ip()

            honeypot = HoneypotInstance(
                id=honeypot_id,
                target_ip=target_ip,
                honeypot_ip=honeypot_ip,
                service_type=service_type,
            )

            if self.simulation_mode:
                self.logger.info(
                    f"[SIM] Created {service_type} honeypot {honeypot_id} "
                    f"for attacker {target_ip}"
                )
            else:
                success = self._create_honeypot_production(honeypot)
                if not success:
                    self.logger.error(
                        f"Failed to create {service_type} honeypot in production"
                    )
                    return None

            self.honeypots[honeypot_id] = honeypot
            return honeypot

        except Exception as e:
            self.logger.error(f"Error creating honeypot: {e}")
            return None

    def _create_honeypot_production(self, honeypot: HoneypotInstance) -> bool:
        """Create honeypot container in production mode."""
        # In production, would use Docker SDK or kubectl
        # For now, just log
        self.logger.info(
            f"[PROD] Creating Docker container for {honeypot.service_type} honeypot"
        )
        return True

    def redirect_traffic(self, src_ip: str, honeypot_id: str) -> bool:
        """
        Redirect traffic from attacker to honeypot.

        Args:
            src_ip: Source IP of attacker
            honeypot_id: ID of honeypot to redirect to

        Returns:
            True if successful
        """
        try:
            if honeypot_id not in self.honeypots:
                self.logger.error(f"Honeypot {honeypot_id} not found")
                return False

            honeypot = self.honeypots[honeypot_id]

            if self.simulation_mode:
                self.redirections[src_ip] = honeypot_id
                # Simulate attacker interaction
                self._simulate_attacker_interaction(honeypot)
                self.logger.info(
                    f"[SIM] Redirected {src_ip} to honeypot {honeypot_id}"
                )
            else:
                # In production, would modify iptables/firewall rules
                self.redirections[src_ip] = honeypot_id
                self.logger.info(
                    f"[PROD] Redirected {src_ip} to honeypot {honeypot.honeypot_ip}"
                )

            return True

        except Exception as e:
            self.logger.error(f"Error redirecting traffic: {e}")
            return False

    def _simulate_attacker_interaction(self, honeypot: HoneypotInstance) -> None:
        """Simulate an attacker interacting with the honeypot."""
        if honeypot.service_type == "ssh":
            self._simulate_ssh_attack(honeypot)
        elif honeypot.service_type == "http":
            self._simulate_http_attack(honeypot)
        elif honeypot.service_type == "ftp":
            self._simulate_ftp_attack(honeypot)
        else:
            honeypot.captured_data.append(f"Connection from {honeypot.target_ip}")

    def _simulate_ssh_attack(self, honeypot: HoneypotInstance) -> None:
        """Simulate SSH brute force and command execution."""
        # Simulate failed login attempts
        for _ in range(random.randint(3, 8)):
            user, passwd = random.choice(self.ssh_credentials)
            honeypot.captured_data.append(
                f"[SSH] Failed login attempt: {user}:{passwd}"
            )

        # Simulate successful login and commands
        user, passwd = random.choice(self.ssh_credentials)
        honeypot.captured_data.append(f"[SSH] Successful login: {user}")

        for _ in range(random.randint(2, 5)):
            cmd = random.choice(self.ssh_commands)
            honeypot.captured_data.append(f"[SSH] Command: {cmd}")

        # Simulate persistence attempt
        honeypot.captured_data.append(
            "[SSH] Attempt to add SSH key: "
            + "ssh-rsa AAAA..." + "".join(random.choices(string.ascii_letters, k=20))
        )

    def _simulate_http_attack(self, honeypot: HoneypotInstance) -> None:
        """Simulate HTTP-based attack (SQL injection, path traversal, etc.)."""
        paths = ["/", "/admin", "/api/users", "/api/login", "/upload", "/search"]
        methods = ["GET", "POST", "PUT", "DELETE"]

        for _ in range(random.randint(3, 8)):
            method = random.choice(methods)
            path = random.choice(paths)
            payload = random.choice(self.http_payloads)
            honeypot.captured_data.append(
                f"[HTTP] {method} {path} - Payload: {payload}"
            )

        # Simulate successful exploitation
        honeypot.captured_data.append("[HTTP] SQL Injection successful - Data exfiltrated")

    def _simulate_ftp_attack(self, honeypot: HoneypotInstance) -> None:
        """Simulate FTP attack."""
        users = ["anonymous", "admin", "ftp", "root"]
        for user in random.sample(users, random.randint(2, 3)):
            honeypot.captured_data.append(f"[FTP] Login attempt: {user}")

        honeypot.captured_data.append("[FTP] Anonymous access granted")
        honeypot.captured_data.append("[FTP] Listed directory: /")

    def get_honeypot_logs(self, honeypot_id: str) -> List[str]:
        """
        Get captured data from a honeypot.

        Args:
            honeypot_id: ID of the honeypot

        Returns:
            List of captured data entries
        """
        if honeypot_id not in self.honeypots:
            self.logger.warning(f"Honeypot {honeypot_id} not found")
            return []

        honeypot = self.honeypots[honeypot_id]
        return honeypot.captured_data.copy()

    def terminate_honeypot(self, honeypot_id: str) -> bool:
        """
        Terminate a honeypot instance.

        Args:
            honeypot_id: ID of the honeypot to terminate

        Returns:
            True if successful
        """
        try:
            if honeypot_id not in self.honeypots:
                self.logger.warning(f"Honeypot {honeypot_id} not found")
                return False

            honeypot = self.honeypots[honeypot_id]
            honeypot.active = False

            # Remove redirections
            for src_ip, hid in list(self.redirections.items()):
                if hid == honeypot_id:
                    del self.redirections[src_ip]

            if self.simulation_mode:
                self.logger.info(f"[SIM] Terminated honeypot {honeypot_id}")
            else:
                self.logger.info(
                    f"[PROD] Terminated honeypot container {honeypot_id}"
                )

            return True

        except Exception as e:
            self.logger.error(f"Error terminating honeypot: {e}")
            return False

    def get_active_honeypots(self) -> List[HoneypotInstance]:
        """Get list of active honeypots."""
        return [
            h for h in self.honeypots.values()
            if h.active
        ]

    def get_attacker_intelligence(self, honeypot_id: str) -> Dict[str, Any]:
        """
        Extract intelligence from honeypot interactions.

        Args:
            honeypot_id: ID of the honeypot

        Returns:
            Dictionary containing attacker intelligence
        """
        if honeypot_id not in self.honeypots:
            return {}

        honeypot = self.honeypots[honeypot_id]
        logs = honeypot.captured_data

        intelligence = {
            "honeypot_id": honeypot_id,
            "attacker_ip": honeypot.target_ip,
            "service_type": honeypot.service_type,
            "created_at": honeypot.created_at.isoformat(),
            "interaction_count": len(logs),
            "attack_techniques": self._extract_attack_techniques(logs),
            "targeted_resources": self._extract_targeted_resources(logs),
            "credentials_attempted": self._extract_credentials(logs),
            "severity_score": self._calculate_severity_score(logs),
            "raw_logs": logs,
        }

        return intelligence

    def _extract_attack_techniques(self, logs: List[str]) -> List[str]:
        """Extract MITRE ATT&CK techniques from logs."""
        techniques = []

        logs_str = " ".join(logs).lower()

        if any(x in logs_str for x in ["ssh", "login attempt"]):
            techniques.append("T1110 - Brute Force")
        if any(x in logs_str for x in ["sql", "injection"]):
            techniques.append("T1190 - Exploit Public-Facing Application")
        if any(x in logs_str for x in ["../", "path traversal"]):
            techniques.append("T1190 - Path Traversal")
        if any(x in logs_str for x in ["ssh key", "authorized_keys"]):
            techniques.append("T1098 - Account Manipulation")
        if any(x in logs_str for x in ["whoami", "id", "uname"]):
            techniques.append("T1082 - System Information Discovery")

        return techniques

    def _extract_targeted_resources(self, logs: List[str]) -> List[str]:
        """Extract targeted resources from logs."""
        resources = set()

        for log in logs:
            log_lower = log.lower()
            if "/etc/passwd" in log_lower:
                resources.add("/etc/passwd")
            if "/etc/shadow" in log_lower:
                resources.add("/etc/shadow")
            if "admin" in log_lower:
                resources.add("/admin")
            if "api" in log_lower:
                resources.add("/api")

        return list(resources)

    def _extract_credentials(self, logs: List[str]) -> Dict[str, int]:
        """Extract and count credential attempts."""
        credentials = {}

        for user, passwd in self.ssh_credentials:
            for log in logs:
                if user in log and passwd in log:
                    key = f"{user}:{passwd}"
                    credentials[key] = credentials.get(key, 0) + 1

        return credentials

    def _calculate_severity_score(self, logs: List[str]) -> float:
        """Calculate severity score based on attacker activity."""
        score = 0.0
        logs_str = " ".join(logs).lower()

        # Brute force attempts
        score += logs_str.count("failed login") * 0.1
        score += logs_str.count("successful login") * 0.3

        # Command execution
        score += logs_str.count("command:") * 0.2

        # Data exfiltration
        score += logs_str.count("exfiltrated") * 0.4

        # Persistence
        score += logs_str.count("ssh key") * 0.35

        return min(1.0, score)

    def _generate_honeypot_ip(self) -> str:
        """Generate a realistic-looking honeypot IP address."""
        return f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}"

    def get_honeypot_summary(self) -> Dict[str, Any]:
        """Get summary of all honeypots."""
        active = self.get_active_honeypots()

        return {
            "total_honeypots": len(self.honeypots),
            "active_honeypots": len(active),
            "total_redirections": len(self.redirections),
            "honeypots_by_service": {},
            "total_captured_interactions": sum(
                len(h.captured_data) for h in active
            ),
        }

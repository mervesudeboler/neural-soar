"""
Attack Profiles - Defines realistic attack scenarios for the simulator.
Each profile represents a different type of network/security attack.
"""
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class AttackProfile:
    """Represents an attack profile with characteristics and detection parameters."""
    name: str
    description: str
    severity: int  # 1-3 (low, medium, high)
    duration_seconds: int
    cpu_impact: float  # 0.0-1.0
    connection_count: int
    port_targets: List[int]
    signatures: List[str]  # IDS signatures associated with attack
    detection_probability: float  # 0.0-1.0 (how easily detected)


# Define all attack profiles
ATTACK_PROFILES: Dict[str, AttackProfile] = {
    "NORMAL_TRAFFIC": AttackProfile(
        name="NORMAL_TRAFFIC",
        description="Normal baseline network traffic",
        severity=1,
        duration_seconds=300,
        cpu_impact=0.05,
        connection_count=50,
        port_targets=[22, 80, 443, 3306, 5432],
        signatures=["baseline_traffic"],
        detection_probability=0.0,
    ),
    "PORT_SCAN_SLOW": AttackProfile(
        name="PORT_SCAN_SLOW",
        description="Slow TCP port scan (nmap -sS style)",
        severity=1,
        duration_seconds=600,
        cpu_impact=0.15,
        connection_count=200,
        port_targets=[
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
            1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017, 6379,
        ],
        signatures=[
            "nmap_syn_scan",
            "slow_port_enumeration",
            "sequential_port_probe",
        ],
        detection_probability=0.4,
    ),
    "PORT_SCAN_FAST": AttackProfile(
        name="PORT_SCAN_FAST",
        description="Fast UDP/TCP port scan (masscan style)",
        severity=1,
        duration_seconds=120,
        cpu_impact=0.4,
        connection_count=5000,
        port_targets=[
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
            1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017, 6379,
        ],
        signatures=[
            "masscan_probe",
            "rapid_port_scan",
            "connection_flood",
        ],
        detection_probability=0.85,
    ),
    "BRUTE_FORCE_SSH": AttackProfile(
        name="BRUTE_FORCE_SSH",
        description="SSH brute force attack (hydra style)",
        severity=2,
        duration_seconds=900,
        cpu_impact=0.25,
        connection_count=1000,
        port_targets=[22],
        signatures=[
            "ssh_brute_force",
            "repeated_login_failures",
            "ssh_invalid_credentials",
            "hydra_ssh_attack",
        ],
        detection_probability=0.9,
    ),
    "DDOS_SYN_FLOOD": AttackProfile(
        name="DDOS_SYN_FLOOD",
        description="SYN flood distributed denial of service",
        severity=3,
        duration_seconds=600,
        cpu_impact=0.8,
        connection_count=50000,
        port_targets=[80, 443],
        signatures=[
            "syn_flood",
            "half_open_connections",
            "tcp_syn_flood_attack",
            "connection_exhaustion",
        ],
        detection_probability=0.95,
    ),
    "DDOS_HTTP_FLOOD": AttackProfile(
        name="DDOS_HTTP_FLOOD",
        description="HTTP flood distributed denial of service",
        severity=3,
        duration_seconds=480,
        cpu_impact=0.75,
        connection_count=10000,
        port_targets=[80, 443, 8080],
        signatures=[
            "http_flood",
            "high_request_rate",
            "http_dos_attack",
            "slowhttptest_attack",
        ],
        detection_probability=0.92,
    ),
    "SQL_INJECTION": AttackProfile(
        name="SQL_INJECTION",
        description="SQL injection web application attack",
        severity=2,
        duration_seconds=300,
        cpu_impact=0.2,
        connection_count=200,
        port_targets=[80, 443, 3000, 5000, 8080],
        signatures=[
            "sql_injection_attempt",
            "sqlmap_attack",
            "sql_metacharacters_in_request",
            "database_error_messages",
            "union_based_injection",
        ],
        detection_probability=0.75,
    ),
    "MALWARE_C2": AttackProfile(
        name="MALWARE_C2",
        description="Malware command and control communication",
        severity=3,
        duration_seconds=1800,
        cpu_impact=0.1,
        connection_count=50,
        port_targets=[443, 8443, 9999],
        signatures=[
            "c2_beacon",
            "botnet_communication",
            "suspicious_ssl_certificate",
            "known_c2_domain",
            "malware_exfiltration",
        ],
        detection_probability=0.7,
    ),
    "LATERAL_MOVEMENT": AttackProfile(
        name="LATERAL_MOVEMENT",
        description="Internal network scanning and lateral movement",
        severity=2,
        duration_seconds=1200,
        cpu_impact=0.15,
        connection_count=300,
        port_targets=[22, 3389, 445, 135, 139],
        signatures=[
            "smb_enumeration",
            "remote_access_attempt",
            "lateral_movement",
            "pass_the_hash",
            "kerberos_exploitation",
        ],
        detection_probability=0.65,
    ),
    "DATA_EXFILTRATION": AttackProfile(
        name="DATA_EXFILTRATION",
        description="Large outbound data transfer (data exfiltration)",
        severity=3,
        duration_seconds=600,
        cpu_impact=0.6,
        connection_count=10,
        port_targets=[443, 21, 22, 25],
        signatures=[
            "large_data_transfer",
            "dns_tunneling",
            "http_data_exfil",
            "sftp_bulk_transfer",
            "uncommon_port_data_transfer",
        ],
        detection_probability=0.8,
    ),
    "PRIVILEGE_ESCALATION": AttackProfile(
        name="PRIVILEGE_ESCALATION",
        description="Privilege escalation exploitation attempts",
        severity=2,
        duration_seconds=300,
        cpu_impact=0.25,
        connection_count=50,
        port_targets=[22, 23, 3389],
        signatures=[
            "sudo_privilege_escalation",
            "suid_exploitation",
            "kernel_exploit_attempt",
            "privilege_escalation_payload",
            "root_access_attempt",
        ],
        detection_probability=0.72,
    ),
}


def get_attack_profile(name: str) -> AttackProfile:
    """
    Retrieve an attack profile by name.

    Args:
        name: Name of the attack profile

    Returns:
        AttackProfile object or None if not found
    """
    return ATTACK_PROFILES.get(name)


def get_all_profiles() -> Dict[str, AttackProfile]:
    """Get all available attack profiles."""
    return ATTACK_PROFILES.copy()


def get_profiles_by_severity(severity: int) -> Dict[str, AttackProfile]:
    """
    Get all profiles with a specific severity level.

    Args:
        severity: Severity level (1-3)

    Returns:
        Dictionary of matching profiles
    """
    return {
        name: profile for name, profile in ATTACK_PROFILES.items()
        if profile.severity == severity
    }


def get_high_severity_profiles() -> Dict[str, AttackProfile]:
    """Get all high-severity (level 3) attack profiles."""
    return get_profiles_by_severity(3)


def get_medium_severity_profiles() -> Dict[str, AttackProfile]:
    """Get all medium-severity (level 2) attack profiles."""
    return get_profiles_by_severity(2)


def get_low_severity_profiles() -> Dict[str, AttackProfile]:
    """Get all low-severity (level 1) attack profiles."""
    return get_profiles_by_severity(1)

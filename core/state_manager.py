"""
System State Manager - Maintains and tracks the current system security state.
Provides normalized observations for RL agents and trend analysis capabilities.
"""

import logging
import threading
from collections import deque
from datetime import datetime
from enum import Enum
from typing import Dict, List, Set, Any, Optional

import numpy as np

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """System threat level enumeration."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class AttackType(Enum):
    """Network attack type enumeration."""
    NONE = 0
    PORT_SCAN = 1
    BRUTE_FORCE = 2
    DDoS = 3
    SQL_INJECTION = 4
    XSS = 5
    MALWARE = 6
    DATA_EXFILTRATION = 7
    PRIVILEGE_ESCALATION = 8
    LATERAL_MOVEMENT = 9
    COMMAND_INJECTION = 10


class SystemStateManager:
    """
    Centralized manager for system security state.
    Tracks all security metrics and provides normalized observations for RL agents.
    Thread-safe with historical state tracking for trend analysis.
    """

    def __init__(self, history_size: int = 1000):
        """
        Initialize the system state manager.

        Args:
            history_size: Number of historical states to maintain for trend analysis.
        """
        self._state_lock = threading.RLock()
        self._history_size = history_size
        self._state_history: deque = deque(maxlen=history_size)

        self._state: Dict[str, Any] = {
            "cpu_load": 0.0,
            "open_ports": [],
            "alert_severity": 0.0,
            "active_connections": 0,
            "attack_type": AttackType.NONE,
            "trust_score": 1.0,
            "honeypot_active": False,
            "isolated_ips": set(),
            "banned_ips": set(),
            "current_threat_level": ThreatLevel.LOW,
            "last_updated": datetime.utcnow(),
        }

        self._record_state()
        logger.info("SystemStateManager initialized")

    def update_state(self, key: str, value: Any) -> None:
        """
        Update a specific state variable.

        Args:
            key: State variable name to update.
            value: New value for the state variable.

        Raises:
            ValueError: If key is not a valid state variable.
        """
        with self._state_lock:
            if key not in self._state:
                logger.warning(f"Attempted to update unknown state key: {key}")
                raise ValueError(f"Unknown state key: {key}")

            old_value = self._state[key]
            self._state[key] = value
            self._state["last_updated"] = datetime.utcnow()

            logger.debug(f"State update: {key} = {value} (was {old_value})")

            if key in ["cpu_load", "alert_severity", "trust_score", "active_connections",
                      "honeypot_active", "current_threat_level"]:
                self._record_state()

    def get_state(self) -> Dict[str, Any]:
        """
        Get a copy of the current system state.

        Returns:
            Dictionary containing all current state variables.
        """
        with self._state_lock:
            state_copy = {
                "cpu_load": self._state["cpu_load"],
                "open_ports": list(self._state["open_ports"]),
                "alert_severity": self._state["alert_severity"],
                "active_connections": self._state["active_connections"],
                "attack_type": self._state["attack_type"],
                "trust_score": self._state["trust_score"],
                "honeypot_active": self._state["honeypot_active"],
                "isolated_ips": set(self._state["isolated_ips"]),
                "banned_ips": set(self._state["banned_ips"]),
                "current_threat_level": self._state["current_threat_level"],
                "last_updated": self._state["last_updated"],
            }
        return state_copy

    def get_rl_observation(self) -> np.ndarray:
        """
        Get normalized state vector for RL agent observation.
        Returns a fixed-size numpy array with normalized values.

        Returns:
            Numpy array of shape (12,) with normalized state features:
            [0]: cpu_load (0-1)
            [1]: num_open_ports (0-65535 normalized)
            [2]: alert_severity (0-1)
            [3]: active_connections (normalized)
            [4]: trust_score (0-1)
            [5]: honeypot_active (0 or 1)
            [6]: num_isolated_ips (normalized)
            [7]: num_banned_ips (normalized)
            [8]: threat_level (0-3 normalized to 0-1)
            [9]: attack_type_id (0-10 normalized to 0-1)
            [10]: connection_avg_trend (trend over last N samples)
            [11]: severity_trend (trend over last N samples)
        """
        with self._state_lock:
            cpu_load = np.clip(self._state["cpu_load"], 0.0, 1.0)
            num_open_ports = np.clip(len(self._state["open_ports"]) / 65535.0, 0.0, 1.0)
            alert_severity = np.clip(self._state["alert_severity"], 0.0, 1.0)
            active_connections = np.clip(self._state["active_connections"] / 1000.0, 0.0, 1.0)
            trust_score = np.clip(self._state["trust_score"], 0.0, 1.0)
            honeypot_active = 1.0 if self._state["honeypot_active"] else 0.0
            num_isolated_ips = np.clip(len(self._state["isolated_ips"]) / 256.0, 0.0, 1.0)
            num_banned_ips = np.clip(len(self._state["banned_ips"]) / 256.0, 0.0, 1.0)
            threat_level = self._state["current_threat_level"].value / 3.0
            attack_type = self._state["attack_type"].value / 10.0

            connection_trend = self._calculate_trend("active_connections")
            severity_trend = self._calculate_trend("alert_severity")

            observation = np.array([
                cpu_load,
                num_open_ports,
                alert_severity,
                active_connections,
                trust_score,
                honeypot_active,
                num_isolated_ips,
                num_banned_ips,
                threat_level,
                attack_type,
                connection_trend,
                severity_trend,
            ], dtype=np.float32)

        return observation

    def _calculate_trend(self, key: str) -> float:
        """
        Calculate trend of a numeric state variable.

        Args:
            key: State key to calculate trend for.

        Returns:
            Normalized trend value (-1 to 1).
        """
        if len(self._state_history) < 2:
            return 0.0

        values = [s.get(key, 0.0) for s in self._state_history]
        if len(values) < 2:
            return 0.0

        recent_avg = np.mean(values[-5:]) if len(values) >= 5 else np.mean(values)
        old_avg = np.mean(values[:5]) if len(values) >= 5 else values[0]

        if old_avg == 0 and recent_avg == 0:
            return 0.0

        trend = (recent_avg - old_avg) / (max(abs(old_avg), 1.0))
        return np.clip(trend, -1.0, 1.0)

    def _record_state(self) -> None:
        """Record current state snapshot in history for trend analysis."""
        state_snapshot = {
            "timestamp": datetime.utcnow(),
            "cpu_load": self._state["cpu_load"],
            "alert_severity": self._state["alert_severity"],
            "active_connections": self._state["active_connections"],
            "trust_score": self._state["trust_score"],
            "threat_level": self._state["current_threat_level"].value,
        }
        self._state_history.append(state_snapshot)

    def add_open_port(self, port: int) -> None:
        """
        Add an open port to the tracking list.

        Args:
            port: Port number to add.
        """
        with self._state_lock:
            if port not in self._state["open_ports"]:
                self._state["open_ports"].append(port)
                self._state["open_ports"].sort()
                logger.debug(f"Open port added: {port}")

    def remove_open_port(self, port: int) -> None:
        """
        Remove a port from the tracking list.

        Args:
            port: Port number to remove.
        """
        with self._state_lock:
            if port in self._state["open_ports"]:
                self._state["open_ports"].remove(port)
                logger.debug(f"Open port removed: {port}")

    def add_isolated_ip(self, ip: str) -> None:
        """
        Add an IP address to the isolated IPs set.

        Args:
            ip: IP address to isolate.
        """
        with self._state_lock:
            self._state["isolated_ips"].add(ip)
            logger.info(f"IP isolated: {ip}")

    def remove_isolated_ip(self, ip: str) -> None:
        """
        Remove an IP address from the isolated IPs set.

        Args:
            ip: IP address to remove from isolation.
        """
        with self._state_lock:
            self._state["isolated_ips"].discard(ip)
            logger.info(f"IP un-isolated: {ip}")

    def add_banned_ip(self, ip: str) -> None:
        """
        Add an IP address to the banned IPs set.

        Args:
            ip: IP address to ban.
        """
        with self._state_lock:
            self._state["banned_ips"].add(ip)
            logger.info(f"IP banned: {ip}")

    def remove_banned_ip(self, ip: str) -> None:
        """
        Remove an IP address from the banned IPs set.

        Args:
            ip: IP address to unban.
        """
        with self._state_lock:
            self._state["banned_ips"].discard(ip)
            logger.info(f"IP un-banned: {ip}")

    def get_isolated_ips(self) -> Set[str]:
        """
        Get a copy of the isolated IPs set.

        Returns:
            Set of isolated IP addresses.
        """
        with self._state_lock:
            return set(self._state["isolated_ips"])

    def get_banned_ips(self) -> Set[str]:
        """
        Get a copy of the banned IPs set.

        Returns:
            Set of banned IP addresses.
        """
        with self._state_lock:
            return set(self._state["banned_ips"])

    def get_open_ports(self) -> List[int]:
        """
        Get a copy of the open ports list.

        Returns:
            List of open port numbers.
        """
        with self._state_lock:
            return list(self._state["open_ports"])

    def reset(self) -> None:
        """
        Reset the system state to initial values.
        Clears history and resets all metrics.
        """
        with self._state_lock:
            self._state = {
                "cpu_load": 0.0,
                "open_ports": [],
                "alert_severity": 0.0,
                "active_connections": 0,
                "attack_type": AttackType.NONE,
                "trust_score": 1.0,
                "honeypot_active": False,
                "isolated_ips": set(),
                "banned_ips": set(),
                "current_threat_level": ThreatLevel.LOW,
                "last_updated": datetime.utcnow(),
            }
            self._state_history.clear()
            self._record_state()
            logger.info("SystemStateManager reset to initial state")

    def get_state_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get historical state snapshots.

        Args:
            limit: Maximum number of recent snapshots to return. None for all.

        Returns:
            List of state snapshots with timestamp and key metrics.
        """
        with self._state_lock:
            history = list(self._state_history)

        if limit is not None:
            history = history[-limit:]

        return history

    def get_state_statistics(self) -> Dict[str, Dict[str, float]]:
        """
        Calculate statistics over the state history.

        Returns:
            Dictionary with min/max/mean/std for key numeric metrics.
        """
        with self._state_lock:
            history = list(self._state_history)

        if not history:
            return {}

        cpu_loads = [s.get("cpu_load", 0.0) for s in history]
        severities = [s.get("alert_severity", 0.0) for s in history]
        connections = [s.get("active_connections", 0) for s in history]
        trust_scores = [s.get("trust_score", 1.0) for s in history]

        def calc_stats(values):
            return {
                "min": float(np.min(values)),
                "max": float(np.max(values)),
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
            }

        return {
            "cpu_load": calc_stats(cpu_loads),
            "alert_severity": calc_stats(severities),
            "active_connections": calc_stats(connections),
            "trust_score": calc_stats(trust_scores),
        }

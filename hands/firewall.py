"""
Firewall Manager - Manages firewall rules and IP blocking/rate limiting.
Supports both simulation and production modes (iptables/nftables).
"""
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional


@dataclass
class BlockRecord:
    """Record of an IP block."""
    ip: str
    blocked_at: datetime = field(default_factory=datetime.utcnow)
    duration: int  # seconds
    reason: str = "Security threat"

    def is_expired(self) -> bool:
        """Check if block has expired."""
        expiry_time = self.blocked_at + timedelta(seconds=self.duration)
        return datetime.utcnow() > expiry_time

    def get_time_remaining(self) -> int:
        """Get remaining block time in seconds."""
        expiry_time = self.blocked_at + timedelta(seconds=self.duration)
        remaining = (expiry_time - datetime.utcnow()).total_seconds()
        return max(0, int(remaining))


class FirewallManager:
    """
    Manages firewall rules for blocking and rate limiting IPs.
    In simulation mode: operates in memory.
    In production mode: uses iptables/nftables commands.
    """

    def __init__(self, simulation_mode: bool = True, use_nftables: bool = False):
        """
        Initialize the firewall manager.

        Args:
            simulation_mode: Whether to run in simulation mode
            use_nftables: Use nftables instead of iptables in production mode
        """
        self.simulation_mode = simulation_mode
        self.use_nftables = use_nftables

        # In-memory storage for simulation mode
        self.blocked_ips: Dict[str, BlockRecord] = {}
        self.rate_limited_ips: Dict[str, Dict] = {}

        self.logger = logging.getLogger(__name__)

    def block_ip(self, ip: str, duration_seconds: int = 3600) -> bool:
        """
        Block traffic from a specific IP address.

        Args:
            ip: IP address to block
            duration_seconds: Block duration in seconds

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.simulation_mode:
                return self._block_ip_simulation(ip, duration_seconds)
            else:
                return self._block_ip_production(ip, duration_seconds)
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip}: {e}")
            return False

    def _block_ip_simulation(self, ip: str, duration_seconds: int) -> bool:
        """Simulate blocking an IP in memory."""
        self.blocked_ips[ip] = BlockRecord(ip=ip, duration=duration_seconds)
        self.logger.info(f"[SIM] Blocked IP {ip} for {duration_seconds}s")
        return True

    def _block_ip_production(self, ip: str, duration_seconds: int) -> bool:
        """Actually block IP using iptables/nftables."""
        try:
            if self.use_nftables:
                cmd = [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "filter",
                    "input",
                    f"ip saddr {ip}",
                    "drop",
                ]
            else:
                cmd = [
                    "iptables",
                    "-I",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                ]

            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            self.blocked_ips[ip] = BlockRecord(ip=ip, duration=duration_seconds)

            # Schedule unblock
            if duration_seconds > 0:
                self.logger.info(
                    f"[PROD] Blocked IP {ip} for {duration_seconds}s via "
                    f"{'nftables' if self.use_nftables else 'iptables'}"
                )

            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"iptables/nftables error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error blocking IP in production: {e}")
            return False

    def rate_limit_ip(self, ip: str, rate: str = "100/sec") -> bool:
        """
        Rate limit traffic from a specific IP.

        Args:
            ip: IP address to rate limit
            rate: Rate limit string (e.g., "100/sec", "10/min")

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.simulation_mode:
                return self._rate_limit_simulation(ip, rate)
            else:
                return self._rate_limit_production(ip, rate)
        except Exception as e:
            self.logger.error(f"Error rate limiting IP {ip}: {e}")
            return False

    def _rate_limit_simulation(self, ip: str, rate: str) -> bool:
        """Simulate rate limiting in memory."""
        self.rate_limited_ips[ip] = {
            "rate": rate,
            "applied_at": datetime.utcnow(),
        }
        self.logger.info(f"[SIM] Rate limited {ip} to {rate}")
        return True

    def _rate_limit_production(self, ip: str, rate: str) -> bool:
        """Actually rate limit using iptables/nftables."""
        try:
            if self.use_nftables:
                # nftables limit syntax
                cmd = [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "filter",
                    "input",
                    f"ip saddr {ip}",
                    f"limit rate {rate}",
                    "accept",
                ]
            else:
                # iptables with limit module
                rate_parts = rate.split("/")
                rate_value = rate_parts[0] if rate_parts else "100"

                cmd = [
                    "iptables",
                    "-I",
                    "INPUT",
                    "-s",
                    ip,
                    "-m",
                    "limit",
                    "--limit",
                    rate,
                    "-j",
                    "ACCEPT",
                ]

            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            self.rate_limited_ips[ip] = {
                "rate": rate,
                "applied_at": datetime.utcnow(),
            }

            self.logger.info(
                f"[PROD] Rate limited {ip} to {rate} via "
                f"{'nftables' if self.use_nftables else 'iptables'}"
            )
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"iptables/nftables error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error rate limiting in production: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock a previously blocked IP.

        Args:
            ip: IP address to unblock

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.simulation_mode:
                return self._unblock_ip_simulation(ip)
            else:
                return self._unblock_ip_production(ip)
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip}: {e}")
            return False

    def _unblock_ip_simulation(self, ip: str) -> bool:
        """Simulate unblocking in memory."""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self.logger.info(f"[SIM] Unblocked IP {ip}")
            return True
        return False

    def _unblock_ip_production(self, ip: str) -> bool:
        """Actually unblock using iptables/nftables."""
        try:
            if self.use_nftables:
                cmd = [
                    "nft",
                    "delete",
                    "rule",
                    "inet",
                    "filter",
                    "input",
                    f"ip saddr {ip}",
                ]
            else:
                cmd = [
                    "iptables",
                    "-D",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                ]

            subprocess.run(cmd, check=True, capture_output=True, timeout=5)

            if ip in self.blocked_ips:
                del self.blocked_ips[ip]

            self.logger.info(
                f"[PROD] Unblocked IP {ip} via "
                f"{'nftables' if self.use_nftables else 'iptables'}"
            )
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"iptables/nftables error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error unblocking in production: {e}")
            return False

    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs."""
        self.flush_expired_blocks()
        return list(self.blocked_ips.keys())

    def get_rate_limited_ips(self) -> List[str]:
        """Get list of currently rate-limited IPs."""
        return list(self.rate_limited_ips.keys())

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        self.flush_expired_blocks()
        return ip in self.blocked_ips

    def flush_expired_blocks(self) -> None:
        """Remove expired blocks from the list."""
        expired_ips = []
        for ip, record in self.blocked_ips.items():
            if record.is_expired():
                expired_ips.append(ip)

        for ip in expired_ips:
            self.unblock_ip(ip)
            self.logger.info(f"Block expired for {ip}")

    def get_block_info(self, ip: str) -> Optional[Dict]:
        """Get detailed block information for an IP."""
        self.flush_expired_blocks()

        if ip not in self.blocked_ips:
            return None

        record = self.blocked_ips[ip]
        return {
            "ip": ip,
            "blocked_at": record.blocked_at.isoformat(),
            "duration": record.duration,
            "reason": record.reason,
            "time_remaining": record.get_time_remaining(),
            "is_expired": record.is_expired(),
        }

    def get_firewall_status(self) -> Dict:
        """Get overall firewall status."""
        self.flush_expired_blocks()

        return {
            "mode": "simulation" if self.simulation_mode else "production",
            "firewall_tool": "nftables" if self.use_nftables else "iptables",
            "blocked_ips_count": len(self.blocked_ips),
            "rate_limited_ips_count": len(self.rate_limited_ips),
            "blocked_ips": list(self.blocked_ips.keys()),
            "rate_limited_ips": list(self.rate_limited_ips.keys()),
        }

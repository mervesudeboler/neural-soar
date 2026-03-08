"""
Action Engine - Central dispatcher for executing RL agent decisions.
Routes actions to appropriate managers and tracks execution history.
"""
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
import json


class ActionType(Enum):
    """Enumeration of possible defensive actions."""
    MONITOR = 0
    RATE_LIMIT = 1
    BLOCK_IP = 2
    REDIRECT_HONEYPOT = 3
    ISOLATE_CONTAINER = 4


@dataclass
class ActionResult:
    """Result of executing a defensive action."""
    action_id: int
    action_name: str
    target_ip: Optional[str]
    success: bool
    execution_time_ms: float
    message: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "action_id": self.action_id,
            "action_name": self.action_name,
            "target_ip": self.target_ip,
            "success": self.success,
            "execution_time_ms": self.execution_time_ms,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
        }


class ActionEngine:
    """
    Central dispatcher for executing defensive actions.
    Receives action decisions from the RL agent and routes them to appropriate managers.
    """

    def __init__(
        self,
        firewall_manager=None,
        honeypot_manager=None,
        container_isolator=None,
        simulation_mode: bool = True,
    ):
        """
        Initialize the action engine.

        Args:
            firewall_manager: FirewallManager instance
            honeypot_manager: HoneypotManager instance
            container_isolator: ContainerIsolator instance
            simulation_mode: Whether running in simulation mode
        """
        self.firewall_manager = firewall_manager
        self.honeypot_manager = honeypot_manager
        self.container_isolator = container_isolator
        self.simulation_mode = simulation_mode

        self.action_history: List[ActionResult] = []
        self.logger = logging.getLogger(__name__)

        # Action statistics
        self.action_counts: Dict[str, int] = {
            "MONITOR": 0,
            "RATE_LIMIT": 0,
            "BLOCK_IP": 0,
            "REDIRECT_HONEYPOT": 0,
            "ISOLATE_CONTAINER": 0,
        }
        self.action_success_counts: Dict[str, int] = {
            "MONITOR": 0,
            "RATE_LIMIT": 0,
            "BLOCK_IP": 0,
            "REDIRECT_HONEYPOT": 0,
            "ISOLATE_CONTAINER": 0,
        }
        self.total_execution_time_ms: Dict[str, float] = {
            "MONITOR": 0.0,
            "RATE_LIMIT": 0.0,
            "BLOCK_IP": 0.0,
            "REDIRECT_HONEYPOT": 0.0,
            "ISOLATE_CONTAINER": 0.0,
        }

    def execute_action(self, action_id: int, context: dict) -> ActionResult:
        """
        Execute a defensive action based on action ID and context.

        Args:
            action_id: Action type ID (0-4)
            context: Context dictionary containing:
                - target_ip: IP address to act on
                - source_ip: Source of the threat
                - reason: Reason for the action
                - duration: Duration for temporary actions
                - service_type: Type of service (for honeypot)
                - container_id: Container ID (for isolation)

        Returns:
            ActionResult with execution details
        """
        start_time = time.time()

        try:
            action_name = ActionType(action_id).name
        except ValueError:
            action_name = "UNKNOWN"
            return ActionResult(
                action_id=action_id,
                action_name=action_name,
                target_ip=context.get("target_ip"),
                success=False,
                execution_time_ms=0,
                message=f"Invalid action ID: {action_id}",
            )

        # Route to appropriate handler
        if action_id == ActionType.MONITOR.value:
            result = self._execute_monitor(context)
        elif action_id == ActionType.RATE_LIMIT.value:
            result = self._execute_rate_limit(context)
        elif action_id == ActionType.BLOCK_IP.value:
            result = self._execute_block_ip(context)
        elif action_id == ActionType.REDIRECT_HONEYPOT.value:
            result = self._execute_redirect_honeypot(context)
        elif action_id == ActionType.ISOLATE_CONTAINER.value:
            result = self._execute_isolate_container(context)
        else:
            result = ActionResult(
                action_id=action_id,
                action_name=action_name,
                target_ip=context.get("target_ip"),
                success=False,
                execution_time_ms=0,
                message="Unknown action type",
            )

        # Calculate execution time
        execution_time_ms = (time.time() - start_time) * 1000
        result.execution_time_ms = execution_time_ms

        # Update statistics
        self.action_counts[action_name] += 1
        if result.success:
            self.action_success_counts[action_name] += 1
        self.total_execution_time_ms[action_name] += execution_time_ms

        # Store in history
        self.action_history.append(result)

        # Log the action
        self.logger.info(
            f"Action executed: {action_name} | "
            f"Target: {result.target_ip} | "
            f"Success: {result.success} | "
            f"Time: {execution_time_ms:.2f}ms"
        )

        return result

    def _execute_monitor(self, context: dict) -> ActionResult:
        """Monitor network/system without taking defensive action."""
        target_ip = context.get("target_ip", "N/A")
        reason = context.get("reason", "Baseline monitoring")

        if self.simulation_mode:
            message = f"Monitoring traffic from {target_ip}: {reason}"
            success = True
        else:
            message = f"Monitoring enabled for {target_ip}"
            success = True

        return ActionResult(
            action_id=ActionType.MONITOR.value,
            action_name="MONITOR",
            target_ip=target_ip,
            success=success,
            execution_time_ms=0,
            message=message,
        )

    def _execute_rate_limit(self, context: dict) -> ActionResult:
        """Rate limit traffic from a specific IP."""
        target_ip = context.get("target_ip", "0.0.0.0")
        rate = context.get("rate", "100/sec")

        if not self.firewall_manager:
            return ActionResult(
                action_id=ActionType.RATE_LIMIT.value,
                action_name="RATE_LIMIT",
                target_ip=target_ip,
                success=False,
                execution_time_ms=0,
                message="FirewallManager not initialized",
            )

        success = self.firewall_manager.rate_limit_ip(target_ip, rate)
        message = (
            f"Rate limited {target_ip} to {rate}"
            if success
            else f"Failed to rate limit {target_ip}"
        )

        return ActionResult(
            action_id=ActionType.RATE_LIMIT.value,
            action_name="RATE_LIMIT",
            target_ip=target_ip,
            success=success,
            execution_time_ms=0,
            message=message,
        )

    def _execute_block_ip(self, context: dict) -> ActionResult:
        """Block traffic from a specific IP."""
        target_ip = context.get("target_ip", "0.0.0.0")
        duration_seconds = context.get("duration", 3600)
        reason = context.get("reason", "Security threat detected")

        if not self.firewall_manager:
            return ActionResult(
                action_id=ActionType.BLOCK_IP.value,
                action_name="BLOCK_IP",
                target_ip=target_ip,
                success=False,
                execution_time_ms=0,
                message="FirewallManager not initialized",
            )

        success = self.firewall_manager.block_ip(target_ip, duration_seconds)
        message = (
            f"Blocked {target_ip} for {duration_seconds}s: {reason}"
            if success
            else f"Failed to block {target_ip}"
        )

        return ActionResult(
            action_id=ActionType.BLOCK_IP.value,
            action_name="BLOCK_IP",
            target_ip=target_ip,
            success=success,
            execution_time_ms=0,
            message=message,
        )

    def _execute_redirect_honeypot(self, context: dict) -> ActionResult:
        """Redirect attacker traffic to a honeypot."""
        target_ip = context.get("target_ip", "0.0.0.0")
        service_type = context.get("service_type", "ssh")
        source_ip = context.get("source_ip", "0.0.0.0")

        if not self.honeypot_manager:
            return ActionResult(
                action_id=ActionType.REDIRECT_HONEYPOT.value,
                action_name="REDIRECT_HONEYPOT",
                target_ip=target_ip,
                success=False,
                execution_time_ms=0,
                message="HoneypotManager not initialized",
            )

        # Create honeypot instance
        honeypot = self.honeypot_manager.create_honeypot(source_ip, service_type)
        if not honeypot or not honeypot.id:
            return ActionResult(
                action_id=ActionType.REDIRECT_HONEYPOT.value,
                action_name="REDIRECT_HONEYPOT",
                target_ip=target_ip,
                success=False,
                execution_time_ms=0,
                message=f"Failed to create honeypot for {service_type}",
            )

        # Redirect traffic
        success = self.honeypot_manager.redirect_traffic(source_ip, honeypot.id)
        message = (
            f"Redirected {source_ip} to honeypot {honeypot.id} ({service_type})"
            if success
            else f"Failed to redirect {source_ip} to honeypot"
        )

        return ActionResult(
            action_id=ActionType.REDIRECT_HONEYPOT.value,
            action_name="REDIRECT_HONEYPOT",
            target_ip=target_ip,
            success=success,
            execution_time_ms=0,
            message=message,
        )

    def _execute_isolate_container(self, context: dict) -> ActionResult:
        """Isolate a potentially compromised container."""
        container_id = context.get("container_id", "unknown")
        reason = context.get("reason", "Suspected compromise")

        if not self.container_isolator:
            return ActionResult(
                action_id=ActionType.ISOLATE_CONTAINER.value,
                action_name="ISOLATE_CONTAINER",
                target_ip=context.get("target_ip"),
                success=False,
                execution_time_ms=0,
                message="ContainerIsolator not initialized",
            )

        success = self.container_isolator.isolate_container(container_id, reason)
        message = (
            f"Isolated container {container_id}: {reason}"
            if success
            else f"Failed to isolate container {container_id}"
        )

        return ActionResult(
            action_id=ActionType.ISOLATE_CONTAINER.value,
            action_name="ISOLATE_CONTAINER",
            target_ip=context.get("target_ip"),
            success=success,
            execution_time_ms=0,
            message=message,
        )

    def get_action_statistics(self) -> Dict[str, Any]:
        """Get comprehensive action statistics."""
        total_actions = sum(self.action_counts.values())
        total_successes = sum(self.action_success_counts.values())

        stats = {
            "total_actions": total_actions,
            "total_successes": total_successes,
            "success_rate": (
                (total_successes / total_actions * 100)
                if total_actions > 0
                else 0
            ),
            "actions_by_type": {},
        }

        for action_name in self.action_counts:
            count = self.action_counts[action_name]
            successes = self.action_success_counts[action_name]
            avg_time = (
                self.total_execution_time_ms[action_name] / count
                if count > 0
                else 0
            )

            stats["actions_by_type"][action_name] = {
                "count": count,
                "successes": successes,
                "success_rate": (successes / count * 100) if count > 0 else 0,
                "avg_execution_time_ms": avg_time,
                "total_execution_time_ms": self.total_execution_time_ms[action_name],
            }

        return stats

    def get_recent_actions(self, n: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent N actions."""
        recent = self.action_history[-n:]
        return [action.to_dict() for action in recent]

    def clear_history(self) -> None:
        """Clear action history."""
        self.action_history.clear()

    def reset_statistics(self) -> None:
        """Reset all statistics."""
        for key in self.action_counts:
            self.action_counts[key] = 0
            self.action_success_counts[key] = 0
            self.total_execution_time_ms[key] = 0.0

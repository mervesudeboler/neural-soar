"""
Metrics Collector - Comprehensive metrics tracking for Neural SOAR system.
Tracks security outcomes, RL agent performance, and system health metrics.
"""

import json
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class ActionMetric:
    """Data class for individual action metrics."""
    timestamp: str
    action_type: str
    latency_ms: float
    was_correct: bool
    latency_percentile: float = field(default=0.0)


@dataclass
class RewardMetric:
    """Data class for individual reward metrics."""
    timestamp: str
    episode_num: int
    reward: float
    cumulative_reward: float


class MetricsCollector:
    """
    Comprehensive metrics collector for Neural SOAR system.
    Tracks security events, RL performance, and system health metrics.
    Thread-safe with JSON export capability.
    """

    def __init__(self):
        """Initialize the metrics collector."""
        self._lock = threading.RLock()

        self._total_attacks_detected = 0
        self._total_attacks_blocked = 0
        self._total_honeypot_redirects = 0
        self._false_positives = 0
        self._true_positives = 0
        self._response_latency_ms: List[float] = []
        self._cumulative_reward = 0.0
        self._episode_count = 0
        self._system_uptime_score = 1.0

        self._action_history: List[ActionMetric] = []
        self._reward_history: List[RewardMetric] = []

        self._creation_time = datetime.utcnow()

        logger.info("MetricsCollector initialized")

    def record_action(self, action_type: str, latency_ms: float, was_correct: bool) -> None:
        """
        Record an action taken by the system.

        Args:
            action_type: Type of action (e.g., 'block_ip', 'isolate_system', 'activate_honeypot').
            latency_ms: Response latency in milliseconds.
            was_correct: Whether the action was the correct response (for RL accuracy).
        """
        with self._lock:
            self._response_latency_ms.append(latency_ms)
            latency_percentile = self._calculate_latency_percentile(latency_ms)

            metric = ActionMetric(
                timestamp=datetime.utcnow().isoformat(),
                action_type=action_type,
                latency_ms=latency_ms,
                was_correct=was_correct,
                latency_percentile=latency_percentile,
            )
            self._action_history.append(metric)

            self._total_attacks_detected += 1

            if was_correct:
                self._true_positives += 1
            else:
                self._false_positives += 1

            if action_type.startswith("block") or action_type.startswith("isolate"):
                self._total_attacks_blocked += 1
            elif action_type == "activate_honeypot":
                self._total_honeypot_redirects += 1

            logger.debug(f"Action recorded: {action_type} (latency={latency_ms}ms, correct={was_correct})")

    def record_reward(self, reward: float) -> None:
        """
        Record reward from the RL training environment.

        Args:
            reward: Reward value for the current RL step.
        """
        with self._lock:
            self._cumulative_reward += reward
            self._episode_count += 1

            metric = RewardMetric(
                timestamp=datetime.utcnow().isoformat(),
                episode_num=self._episode_count,
                reward=reward,
                cumulative_reward=self._cumulative_reward,
            )
            self._reward_history.append(metric)

            logger.debug(f"Reward recorded: {reward} (cumulative={self._cumulative_reward}, episode={self._episode_count})")

    def get_summary(self) -> Dict[str, any]:
        """
        Get comprehensive summary of all metrics.

        Returns:
            Dictionary containing all tracked metrics and statistics.
        """
        with self._lock:
            total_actions = self._total_attacks_detected
            accuracy = (self._true_positives / total_actions) if total_actions > 0 else 0.0
            false_positive_rate = (self._false_positives / total_actions) if total_actions > 0 else 0.0

            avg_latency = (
                np.mean(self._response_latency_ms) if self._response_latency_ms else 0.0
            )
            p95_latency = (
                float(np.percentile(self._response_latency_ms, 95))
                if self._response_latency_ms else 0.0
            )
            p99_latency = (
                float(np.percentile(self._response_latency_ms, 99))
                if self._response_latency_ms else 0.0
            )

            uptime_seconds = (datetime.utcnow() - self._creation_time).total_seconds()
            uptime_hours = uptime_seconds / 3600.0

            summary = {
                "timestamp": datetime.utcnow().isoformat(),
                "uptime_hours": uptime_hours,
                "security_metrics": {
                    "total_attacks_detected": self._total_attacks_detected,
                    "total_attacks_blocked": self._total_attacks_blocked,
                    "total_honeypot_redirects": self._total_honeypot_redirects,
                    "true_positives": self._true_positives,
                    "false_positives": self._false_positives,
                    "detection_accuracy": float(accuracy),
                    "false_positive_rate": float(false_positive_rate),
                },
                "response_metrics": {
                    "average_latency_ms": float(avg_latency),
                    "p95_latency_ms": float(p95_latency),
                    "p99_latency_ms": float(p99_latency),
                    "total_responses": len(self._response_latency_ms),
                },
                "rl_metrics": {
                    "cumulative_reward": float(self._cumulative_reward),
                    "episode_count": self._episode_count,
                    "average_reward_per_episode": (
                        float(self._cumulative_reward / self._episode_count)
                        if self._episode_count > 0 else 0.0
                    ),
                },
                "system_health": {
                    "uptime_score": float(self._system_uptime_score),
                    "security_score": float(self.get_security_score()),
                },
            }

        return summary

    def get_autonomous_response_latency(self) -> float:
        """
        Get average autonomous response latency in milliseconds.

        Returns:
            Average response latency across all recorded actions.
        """
        with self._lock:
            if not self._response_latency_ms:
                return 0.0
            return float(np.mean(self._response_latency_ms))

    def get_security_score(self) -> float:
        """
        Calculate composite security score (0-100).

        Combines detection rate, response accuracy, and blocking effectiveness.

        Returns:
            Security score from 0 to 100.
        """
        with self._lock:
            if self._total_attacks_detected == 0:
                return 100.0

            detection_rate = min(1.0, self._total_attacks_detected / max(1, self._total_attacks_detected))
            blocking_rate = (self._total_attacks_blocked / self._total_attacks_detected)
            accuracy = (self._true_positives / self._total_attacks_detected)

            weighted_score = (
                (detection_rate * 0.3) +
                (blocking_rate * 0.35) +
                (accuracy * 0.35)
            )

            return float(min(100.0, weighted_score * 100.0))

    def get_detection_rate(self) -> float:
        """
        Get detection rate (fraction of attacks detected).

        Returns:
            Detection rate from 0.0 to 1.0.
        """
        with self._lock:
            if self._total_attacks_detected == 0:
                return 0.0
            return float(self._total_attacks_blocked / self._total_attacks_detected)

    def get_accuracy(self) -> float:
        """
        Get action accuracy (fraction of correct actions).

        Returns:
            Accuracy from 0.0 to 1.0.
        """
        with self._lock:
            if self._total_attacks_detected == 0:
                return 0.0
            return float(self._true_positives / self._total_attacks_detected)

    def get_false_positive_rate(self) -> float:
        """
        Get false positive rate.

        Returns:
            False positive rate from 0.0 to 1.0.
        """
        with self._lock:
            if self._total_attacks_detected == 0:
                return 0.0
            return float(self._false_positives / self._total_attacks_detected)

    def export_to_json(self, filepath: str) -> None:
        """
        Export all metrics to a JSON file.

        Args:
            filepath: Path where to save the JSON metrics file.
        """
        with self._lock:
            summary = self.get_summary()
            summary["detailed_metrics"] = {
                "actions": [asdict(m) for m in self._action_history],
                "rewards": [asdict(m) for m in self._reward_history],
            }

        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w") as f:
                json.dump(summary, f, indent=2, default=str)

            logger.info(f"Metrics exported to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export metrics to {filepath}: {e}")

    def export_to_dict(self) -> Dict:
        """
        Export all metrics to a dictionary for programmatic access.

        Returns:
            Dictionary containing all metrics and history.
        """
        with self._lock:
            summary = self.get_summary()
            summary["detailed_metrics"] = {
                "actions": [asdict(m) for m in self._action_history],
                "rewards": [asdict(m) for m in self._reward_history],
            }
            return summary

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        with self._lock:
            self._total_attacks_detected = 0
            self._total_attacks_blocked = 0
            self._total_honeypot_redirects = 0
            self._false_positives = 0
            self._true_positives = 0
            self._response_latency_ms.clear()
            self._cumulative_reward = 0.0
            self._episode_count = 0
            self._system_uptime_score = 1.0
            self._action_history.clear()
            self._reward_history.clear()
            self._creation_time = datetime.utcnow()
            logger.info("MetricsCollector reset to initial state")

    def update_system_uptime_score(self, score: float) -> None:
        """
        Update the system uptime score.

        Args:
            score: Uptime score from 0.0 to 1.0.
        """
        with self._lock:
            self._system_uptime_score = np.clip(float(score), 0.0, 1.0)
            logger.debug(f"System uptime score updated to {self._system_uptime_score}")

    def get_action_history(self, action_type: Optional[str] = None, limit: Optional[int] = None) -> List[ActionMetric]:
        """
        Get action history with optional filtering.

        Args:
            action_type: Filter by action type. None for all.
            limit: Maximum number of recent actions to return.

        Returns:
            List of ActionMetric objects.
        """
        with self._lock:
            history = self._action_history

        if action_type is not None:
            history = [a for a in history if a.action_type == action_type]

        if limit is not None:
            history = history[-limit:]

        return history

    def get_reward_history(self, limit: Optional[int] = None) -> List[RewardMetric]:
        """
        Get reward history.

        Args:
            limit: Maximum number of recent rewards to return.

        Returns:
            List of RewardMetric objects.
        """
        with self._lock:
            history = self._reward_history

        if limit is not None:
            history = history[-limit:]

        return history

    def _calculate_latency_percentile(self, current_latency: float) -> float:
        """
        Calculate percentile rank of current latency.

        Args:
            current_latency: The latency value to rank.

        Returns:
            Percentile from 0.0 to 1.0.
        """
        if not self._response_latency_ms:
            return 0.5

        percentile = np.mean(
            [1.0 if latency <= current_latency else 0.0 for latency in self._response_latency_ms]
        )
        return float(percentile)

    def get_performance_metrics_over_time(self, window_size: int = 10) -> Dict[str, List[float]]:
        """
        Get moving average metrics over time.

        Args:
            window_size: Size of moving average window.

        Returns:
            Dictionary with lists of moving averages for key metrics.
        """
        with self._lock:
            if len(self._action_history) < window_size:
                return {}

            accuracy_window = []
            latency_window = []

            for i in range(len(self._action_history) - window_size + 1):
                window_actions = self._action_history[i:i + window_size]

                window_accuracy = (
                    sum(1 for a in window_actions if a.was_correct) / window_size
                )
                window_latency = np.mean([a.latency_ms for a in window_actions])

                accuracy_window.append(window_accuracy)
                latency_window.append(window_latency)

            return {
                "accuracy_moving_avg": accuracy_window,
                "latency_moving_avg": latency_window,
            }

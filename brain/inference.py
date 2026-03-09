"""
SOAR Inference Engine
Runs trained RL agent for real-time security decision making.
"""

import numpy as np
from pathlib import Path
from typing import Dict, Optional, Any, Callable
import logging
from datetime import datetime
import json
import threading
import time
from dataclasses import dataclass, asdict
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class InferenceResult:
    """Result from a single inference run."""
    timestamp: str
    action_id: int
    action_name: str
    confidence: float
    reasoning: str
    response_time_ms: float
    observation: list
    action_probabilities: list


class InferenceStatistics:
    """Tracks inference statistics over time."""

    def __init__(self, max_history: int = 1000):
        """
        Initialize statistics tracker.

        Args:
            max_history: Maximum number of inferences to track
        """
        self.max_history = max_history
        self.inference_times = deque(maxlen=max_history)
        self.action_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        self.decisions = deque(maxlen=max_history)
        self.lock = threading.Lock()

    def record_inference(self, action_id: int, response_time_ms: float,
                        decision: InferenceResult) -> None:
        """
        Record an inference result.

        Args:
            action_id: Action taken
            response_time_ms: Response time in milliseconds
            decision: Complete inference result
        """
        with self.lock:
            self.inference_times.append(response_time_ms)
            self.action_counts[action_id] += 1
            self.decisions.append(decision)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current statistics.

        Returns:
            Dictionary of statistics
        """
        with self.lock:
            if not self.inference_times:
                return {
                    "total_inferences": 0,
                    "avg_latency_ms": 0.0,
                    "min_latency_ms": 0.0,
                    "max_latency_ms": 0.0,
                    "action_distribution": self.action_counts.copy()
                }

            times = list(self.inference_times)
            return {
                "total_inferences": len(times),
                "avg_latency_ms": float(np.mean(times)),
                "min_latency_ms": float(np.min(times)),
                "max_latency_ms": float(np.max(times)),
                "std_latency_ms": float(np.std(times)),
                "action_distribution": self.action_counts.copy()
            }


class RuleBasedInference:
    """Fallback rule-based inference when model not available."""

    def __init__(self):
        """Initialize rule-based inference."""
        self.action_names = {
            0: "MONITOR",
            1: "RATE_LIMIT",
            2: "BLOCK_IP",
            3: "REDIRECT_HONEYPOT",
            4: "ISOLATE_CONTAINER"
        }
        logger.info("RuleBasedInference initialized as fallback")

    def run(self, observation: np.ndarray) -> Dict[str, Any]:
        """
        Run rule-based inference.

        Args:
            observation: Observation vector

        Returns:
            Inference result dict
        """
        start_time = datetime.now()

        threat_level = observation[11]
        failed_login_rate = observation[8]
        cpu_load = observation[0]

        if threat_level > 0.8:
            if failed_login_rate > 0.5:
                action = 2
                reasoning = "Brute force attack detected - blocking IPs"
                confidence = 0.95
            elif cpu_load > 0.7:
                action = 1
                reasoning = "DDoS attack detected - rate limiting"
                confidence = 0.90
            else:
                action = 3
                reasoning = "Unknown attack detected - redirecting to honeypot"
                confidence = 0.85
        elif threat_level > 0.5:
            if failed_login_rate > 0.3:
                action = 2
                reasoning = "Possible brute force attempt - blocking IPs"
                confidence = 0.75
            elif cpu_load > 0.6:
                action = 1
                reasoning = "High load detected - applying rate limiting"
                confidence = 0.70
            else:
                action = 0
                reasoning = "Monitoring elevated threat level"
                confidence = 0.65
        else:
            action = 0
            reasoning = "Normal operation - monitoring"
            confidence = 0.50

        response_time = (datetime.now() - start_time).total_seconds() * 1000

        probs = np.zeros(5, dtype=np.float32)
        probs[action] = confidence
        probs = probs / np.sum(probs)

        return {
            "action_id": action,
            "action_name": self.action_names[action],
            "confidence": float(confidence),
            "reasoning": reasoning,
            "response_time_ms": response_time,
            "action_probabilities": probs.tolist()
        }


class SOARInference:
    """
    SOAR Inference Engine for real-time decision making with trained RL agent.
    """

    def __init__(self, agent, model_path: Optional[str] = None):
        """
        Initialize inference engine.

        Args:
            agent: SOARAgent instance
            model_path: Path to trained model (loads if provided)
        """
        self.agent = agent
        self.statistics = InferenceStatistics()
        self.decision_log = []
        self.inference_active = False

        # Action name mapping
        self.action_names = {
            0: "MONITOR",
            1: "RATE_LIMIT",
            2: "BLOCK_IP",
            3: "REDIRECT_HONEYPOT",
            4: "ISOLATE_CONTAINER"
        }

        # Try to load model
        if model_path:
            try:
                self.agent.load(model_path)
                logger.info(f"Loaded model from {model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}, using rule-based fallback")
                self.agent.model = RuleBasedInference()
        elif isinstance(self.agent.model, type(None)):
            logger.warning("No model available, using rule-based fallback")
            self.agent.model = RuleBasedInference()

        logger.info("SOARInference initialized")

    def run(self, observation: np.ndarray) -> Dict[str, Any]:
        """
        Run inference on observation.

        Args:
            observation: Observation vector of shape (12,)

        Returns:
            Dict with action_id, action_name, confidence, reasoning, response_time_ms
        """
        start_time = datetime.now()

        try:
            # Handle rule-based fallback
            if isinstance(self.agent.model, RuleBasedInference):
                result = self.agent.model.run(observation)
            else:
                # Get prediction from trained model
                action, action_probs = self.agent.predict(observation)

                # Generate reasoning
                reasoning = self._generate_reasoning(observation, action, action_probs)

                result = {
                    "action_id": int(action),
                    "action_name": self.action_names[int(action)],
                    "confidence": float(np.max(action_probs)),
                    "reasoning": reasoning,
                    "action_probabilities": action_probs.tolist()
                }

            # Add response time
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            result["response_time_ms"] = response_time

            # Create full inference result
            inference_result = InferenceResult(
                timestamp=datetime.now().isoformat(),
                action_id=result["action_id"],
                action_name=result["action_name"],
                confidence=result["confidence"],
                reasoning=result["reasoning"],
                response_time_ms=response_time,
                observation=observation.tolist(),
                action_probabilities=result["action_probabilities"]
            )

            # Record statistics
            self.statistics.record_inference(
                result["action_id"],
                response_time,
                inference_result
            )

            # Add to decision log
            self.decision_log.append(asdict(inference_result))

            logger.debug(f"Inference: {result['action_name']} (confidence: {result['confidence']:.2%}, time: {response_time:.2f}ms)")

            return result

        except Exception as e:
            logger.error(f"Inference failed: {e}", exc_info=True)

            # Fallback to safe action
            return {
                "action_id": 0,
                "action_name": "MONITOR",
                "confidence": 0.0,
                "reasoning": f"Inference error - safe fallback: {str(e)}",
                "response_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
                "action_probabilities": [1.0, 0.0, 0.0, 0.0, 0.0]
            }

    def start_live_inference(self,
                            state_manager: Any,
                            action_engine: Optional[Callable] = None,
                            interval_seconds: float = 1.0) -> threading.Thread:
        """
        Start live inference loop in background thread.

        Args:
            state_manager: System state manager to get observations from
            action_engine: Optional callable to execute actions
            interval_seconds: Interval between inferences

        Returns:
            Thread object (already started)
        """
        self.inference_active = True

        def inference_loop():
            """Background inference loop."""
            while self.inference_active:
                try:
                    # Get observation from state manager
                    observation = self._state_to_observation(state_manager)

                    # Run inference
                    result = self.run(observation)

                    # Execute action if engine provided
                    if action_engine:
                        try:
                            action_engine(result["action_id"], result)
                        except Exception as e:
                            logger.error(f"Action execution failed: {e}")

                    # Log decision
                    logger.info(
                        f"Decision: {result['action_name']} | "
                        f"Confidence: {result['confidence']:.2%} | "
                        f"Time: {result['response_time_ms']:.2f}ms"
                    )

                    # Sleep until next interval
                    time.sleep(interval_seconds)

                except Exception as e:
                    logger.error(f"Inference loop error: {e}")
                    time.sleep(interval_seconds)

        # Create and start thread
        thread = threading.Thread(target=inference_loop, daemon=True)
        thread.start()

        logger.info(f"Live inference started (interval: {interval_seconds}s)")
        return thread

    def stop_live_inference(self) -> None:
        """Stop live inference loop."""
        self.inference_active = False
        logger.info("Live inference stopped")

    def explain_decision(self, observation: np.ndarray) -> str:
        """
        Explain why agent made a particular decision.

        Args:
            observation: Observation vector

        Returns:
            Human-readable explanation
        """
        result = self.run(observation)

        explanation = []
        explanation.append("\nDecision Explanation")
        explanation.append("=" * 50)
        explanation.append(f"Action: {result['action_name']}")
        explanation.append(f"Confidence: {result['confidence']:.2%}")
        explanation.append(f"Response Time: {result['response_time_ms']:.2f}ms")
        explanation.append(f"\nReasoning: {result['reasoning']}")

        # Add feature analysis
        explanation.append("\nObservation Analysis:")
        explanation.append(f"  CPU Load: {observation[0]:.2%}")
        explanation.append(f"  Alert Severity: {observation[2]:.2%}")
        explanation.append(f"  Threat Level: {observation[11]:.2%}")
        explanation.append(f"  Trust Score: {observation[5]:.2%}")
        explanation.append(f"  Failed Login Rate: {observation[8]:.2%}")

        explanation.append("\nAction Probabilities:")
        for i, prob in enumerate(result['action_probabilities']):
            explanation.append(f"  {self.action_names[i]}: {prob:.2%}")

        explanation.append("=" * 50 + "\n")

        return "\n".join(explanation)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get inference statistics.

        Returns:
            Dictionary of statistics
        """
        stats = self.statistics.get_statistics()
        stats["total_logged_decisions"] = len(self.decision_log)
        return stats

    def save_decision_log(self, path: str) -> None:
        """
        Save decision log to JSON file.

        Args:
            path: Path to save log
        """
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w") as f:
                json.dump(self.decision_log, f, indent=2)

            logger.info(f"Decision log saved to {path} ({len(self.decision_log)} decisions)")
        except Exception as e:
            logger.error(f"Failed to save decision log: {e}")

    def print_statistics(self) -> None:
        """Print formatted statistics to console."""
        stats = self.get_statistics()

        output = []
        output.append("\n" + "="*60)
        output.append("INFERENCE STATISTICS")
        output.append("="*60)
        output.append(f"Total Inferences: {stats['total_inferences']}")
        output.append(f"Total Logged Decisions: {stats['total_logged_decisions']}")
        output.append("")
        output.append("Latency Statistics:")
        output.append(f"  Average: {stats['avg_latency_ms']:.2f}ms")
        output.append(f"  Min: {stats['min_latency_ms']:.2f}ms")
        output.append(f"  Max: {stats['max_latency_ms']:.2f}ms")
        if 'std_latency_ms' in stats:
            output.append(f"  Std Dev: {stats['std_latency_ms']:.2f}ms")
        output.append("")
        output.append("Action Distribution:")
        action_names = ["MONITOR", "RATE_LIMIT", "BLOCK_IP", "REDIRECT_HONEYPOT", "ISOLATE_CONTAINER"]
        for i, name in enumerate(action_names):
            count = stats['action_distribution'][i]
            pct = (count / stats['total_inferences'] * 100) if stats['total_inferences'] > 0 else 0
            output.append(f"  {name}: {count} ({pct:.1f}%)")
        output.append("="*60 + "\n")

        for line in output:
            print(line)
            logger.info(line)

    @staticmethod
    def _state_to_observation(state_manager: Any) -> np.ndarray:
        """
        Convert system state to observation vector.

        Args:
            state_manager: System state manager

        Returns:
            Observation vector
        """
        try:
            state = state_manager.get_state()

            observation = np.array([
                state.get("cpu_load", 0.3),
                state.get("open_ports", 10) / 65535.0,
                state.get("alert_severity", 0.2),
                state.get("active_connections", 50) / 10000.0,
                state.get("attack_type", 0) / 6.0,
                state.get("trust_score", 0.9),
                float(state.get("honeypot_active", False)),
                state.get("banned_ips", 0) / 10000.0,
                state.get("failed_login_rate", 0.05),
                state.get("connection_rate", 100) / 10000.0,
                min(state.get("system_uptime", 30.0) / 365.0, 1.0),
                state.get("threat_level", 0.1)
            ], dtype=np.float32)

            return np.clip(observation, 0, 1)

        except Exception as e:
            logger.error(f"Failed to convert state to observation: {e}")
            return np.zeros(12, dtype=np.float32)

    def _generate_reasoning(self, observation: np.ndarray, action: int,
                          action_probs: np.ndarray) -> str:
        """
        Generate human-readable reasoning for a decision.

        Args:
            observation: Observation vector
            action: Action ID
            action_probs: Action probabilities

        Returns:
            Reasoning string
        """
        threat_level = observation[11]
        cpu_load = observation[0]
        alert_severity = observation[2]
        failed_login_rate = observation[8]
        trust_score = observation[5]

        action_name = self.action_names[action]
        confidence = float(np.max(action_probs))

        # Build reasoning based on observation features
        factors = []

        if threat_level > 0.7:
            factors.append("high threat level detected")
        elif threat_level > 0.4:
            factors.append("moderate threat detected")

        if cpu_load > 0.7:
            factors.append("high CPU load")

        if alert_severity > 0.6:
            factors.append("elevated alert severity")

        if failed_login_rate > 0.3:
            factors.append("suspicious login attempts")

        if trust_score < 0.4:
            factors.append("low trust score")

        factors_str = ", ".join(factors) if factors else "normal conditions"

        reasoning = f"Selected {action_name} ({confidence:.2%} confidence) based on: {factors_str}"

        return reasoning

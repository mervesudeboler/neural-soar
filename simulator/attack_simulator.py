"""
Attack Simulator - Generates realistic attack scenarios for training RL agents.
Runs attack sequences in background thread and publishes events.
"""
import logging
import random
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any

from .attack_profiles import AttackProfile, ATTACK_PROFILES


@dataclass
class SimulationEvent:
    """Represents a simulation event."""
    event_type: str
    timestamp: str
    attack_profile: str
    source_ip: str
    target_ips: List[str]
    ports: List[int]
    description: str
    severity: int
    event_data: Dict[str, Any]


class AttackSimulator:
    """
    Simulates realistic attack scenarios for training and testing the RL agent.
    Runs attack sequences and generates system state updates.
    """

    # Attack probability weights
    ATTACK_WEIGHTS = {
        "NORMAL_TRAFFIC": 0.40,
        "PORT_SCAN_SLOW": 0.10,
        "PORT_SCAN_FAST": 0.10,
        "BRUTE_FORCE_SSH": 0.15,
        "DDOS_SYN_FLOOD": 0.05,
        "DDOS_HTTP_FLOOD": 0.05,
        "SQL_INJECTION": 0.08,
        "MALWARE_C2": 0.04,
        "LATERAL_MOVEMENT": 0.02,
        "DATA_EXFILTRATION": 0.00,
        "PRIVILEGE_ESCALATION": 0.01,
    }

    def __init__(self, event_bus=None, state_manager=None):
        """
        Initialize the attack simulator.

        Args:
            event_bus: EventBus for publishing simulation events
            state_manager: SystemStateManager for updating state
        """
        self.event_bus = event_bus
        self.state_manager = state_manager

        self.is_running = False
        self.simulation_thread: Optional[threading.Thread] = None

        self.active_scenario: Optional[str] = None
        self.scenario_start_time: Optional[datetime] = None
        self.scenario_duration: int = 0

        self.events_generated: List[SimulationEvent] = []
        self.attack_counts: Dict[str, int] = {name: 0 for name in ATTACK_PROFILES}

        self.logger = logging.getLogger(__name__)

    def start(self) -> None:
        """Start the attack simulator in background thread."""
        if self.is_running:
            self.logger.warning("Simulator is already running")
            return

        self.is_running = True
        self.simulation_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.simulation_thread.start()
        self.logger.info("Attack simulator started")

    def stop(self) -> None:
        """Stop the attack simulator."""
        self.is_running = False
        if self.simulation_thread:
            self.simulation_thread.join(timeout=5)
        self.logger.info("Attack simulator stopped")

    def _run_loop(self) -> None:
        """Main simulation loop running in background thread."""
        while self.is_running:
            try:
                # If no active scenario, start a new random one
                if self.active_scenario is None:
                    profile_name = self._select_weighted_attack()
                    self.run_scenario(profile_name, duration_seconds=30)

                # Check if current scenario has finished
                if self.scenario_start_time and self.active_scenario:
                    elapsed = (datetime.utcnow() - self.scenario_start_time).total_seconds()
                    if elapsed > self.scenario_duration:
                        self.active_scenario = None
                        self.logger.info("Current scenario completed")

                time.sleep(1)

            except Exception as e:
                self.logger.error(f"Error in simulation loop: {e}")
                time.sleep(2)

    def run_scenario(self, profile_name: str, duration_seconds: int = 60) -> bool:
        """
        Run a specific attack scenario.

        Args:
            profile_name: Name of the attack profile to simulate
            duration_seconds: Duration of the scenario

        Returns:
            True if scenario started successfully
        """
        if profile_name not in ATTACK_PROFILES:
            self.logger.error(f"Unknown attack profile: {profile_name}")
            return False

        profile = ATTACK_PROFILES[profile_name]

        self.active_scenario = profile_name
        self.scenario_start_time = datetime.utcnow()
        self.scenario_duration = duration_seconds

        self.logger.info(
            f"Starting scenario: {profile_name} "
            f"(duration: {duration_seconds}s, severity: {profile.severity})"
        )

        # Generate and execute attack sequence
        sequence = self.generate_attack_sequence(profile, steps=10)

        for i, step in enumerate(sequence):
            if not self.is_running:
                break

            # Execute step
            event = self._execute_attack_step(step, profile)
            if event:
                self.events_generated.append(event)

                # Publish event
                if self.event_bus:
                    self.event_bus.publish("attack_detected", asdict(event))

                # Update system state
                if self.state_manager:
                    self._update_system_state(event, profile)

            # Calculate delay between steps
            step_delay = duration_seconds / len(sequence)
            time.sleep(max(0.1, step_delay - 0.1))

        self.attack_counts[profile_name] += 1
        return True

    def run_random_scenario(self) -> bool:
        """
        Run a randomly selected attack scenario based on weighted probabilities.

        Returns:
            True if scenario started successfully
        """
        profile_name = self._select_weighted_attack()
        profile = ATTACK_PROFILES[profile_name]
        return self.run_scenario(profile_name, duration_seconds=profile.duration_seconds)

    def generate_attack_sequence(
        self, profile: AttackProfile, steps: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Generate a realistic attack sequence progression.

        Simulates: reconnaissance → exploitation → persistence.

        Args:
            profile: AttackProfile to generate sequence for
            steps: Number of steps in the sequence

        Returns:
            List of attack steps
        """
        sequence = []

        # Determine attack phases
        recon_steps = max(1, steps // 3)
        exploit_steps = max(1, steps // 3)
        persist_steps = steps - recon_steps - exploit_steps

        # Reconnaissance phase
        for i in range(recon_steps):
            sequence.append({
                "phase": "reconnaissance",
                "step": i + 1,
                "action": self._generate_recon_action(profile),
                "ports": random.sample(profile.port_targets, k=min(2, len(profile.port_targets))),
                "intensity": 0.3 + (i / recon_steps) * 0.2,
            })

        # Exploitation phase
        for i in range(exploit_steps):
            sequence.append({
                "phase": "exploitation",
                "step": i + 1,
                "action": self._generate_exploit_action(profile),
                "ports": random.sample(profile.port_targets, k=min(3, len(profile.port_targets))),
                "intensity": 0.5 + (i / exploit_steps) * 0.3,
            })

        # Persistence phase
        for i in range(persist_steps):
            sequence.append({
                "phase": "persistence",
                "step": i + 1,
                "action": self._generate_persistence_action(profile),
                "ports": random.sample(profile.port_targets, k=1),
                "intensity": 0.2 + (i / persist_steps) * 0.1,
            })

        return sequence

    def _generate_recon_action(self, profile: AttackProfile) -> str:
        """Generate a reconnaissance action for the given profile."""
        recon_actions = {
            "PORT_SCAN_SLOW": "slow_port_enumeration",
            "PORT_SCAN_FAST": "rapid_port_scan",
            "BRUTE_FORCE_SSH": "service_enumeration",
            "DDOS_SYN_FLOOD": "target_discovery",
            "DDOS_HTTP_FLOOD": "web_service_probing",
            "SQL_INJECTION": "web_service_discovery",
            "MALWARE_C2": "network_analysis",
            "LATERAL_MOVEMENT": "internal_network_scan",
            "DATA_EXFILTRATION": "data_discovery",
            "PRIVILEGE_ESCALATION": "permission_enumeration",
            "NORMAL_TRAFFIC": "baseline_communication",
        }
        return recon_actions.get(profile.name, "network_recon")

    def _generate_exploit_action(self, profile: AttackProfile) -> str:
        """Generate an exploitation action for the given profile."""
        exploit_actions = {
            "PORT_SCAN_SLOW": "service_vulnerability_check",
            "PORT_SCAN_FAST": "service_vulnerability_scan",
            "BRUTE_FORCE_SSH": "credential_attack",
            "DDOS_SYN_FLOOD": "syn_flood_launch",
            "DDOS_HTTP_FLOOD": "http_flood_launch",
            "SQL_INJECTION": "sql_injection_attempt",
            "MALWARE_C2": "c2_command_execution",
            "LATERAL_MOVEMENT": "credential_theft",
            "DATA_EXFILTRATION": "data_extraction",
            "PRIVILEGE_ESCALATION": "exploit_execution",
            "NORMAL_TRAFFIC": "normal_operation",
        }
        return exploit_actions.get(profile.name, "exploitation")

    def _generate_persistence_action(self, profile: AttackProfile) -> str:
        """Generate a persistence action for the given profile."""
        persistence_actions = {
            "PORT_SCAN_SLOW": "vulnerability_documentation",
            "PORT_SCAN_FAST": "vulnerability_documentation",
            "BRUTE_FORCE_SSH": "backdoor_account_creation",
            "DDOS_SYN_FLOOD": "botnet_integration",
            "DDOS_HTTP_FLOOD": "botnet_integration",
            "SQL_INJECTION": "database_modification",
            "MALWARE_C2": "c2_persistence",
            "LATERAL_MOVEMENT": "remote_access_persistence",
            "DATA_EXFILTRATION": "ongoing_exfiltration",
            "PRIVILEGE_ESCALATION": "root_persistence",
            "NORMAL_TRAFFIC": "continued_operation",
        }
        return persistence_actions.get(profile.name, "persistence")

    def _execute_attack_step(
        self, step: Dict[str, Any], profile: AttackProfile
    ) -> Optional[SimulationEvent]:
        """Execute a single attack step and generate event."""
        try:
            source_ip = self._generate_attacker_ip()
            target_ips = [self._generate_target_ip() for _ in range(2)]

            event = SimulationEvent(
                event_type="attack_detected",
                timestamp=datetime.utcnow().isoformat(),
                attack_profile=profile.name,
                source_ip=source_ip,
                target_ips=target_ips,
                ports=step["ports"],
                description=f"{step['phase'].title()}: {step['action']}",
                severity=profile.severity,
                event_data={
                    "phase": step["phase"],
                    "action": step["action"],
                    "intensity": step["intensity"],
                    "signatures": random.sample(profile.signatures, k=min(2, len(profile.signatures))),
                    "connection_count": int(profile.connection_count * step["intensity"]),
                    "cpu_impact": profile.cpu_impact * step["intensity"],
                },
            )

            return event

        except Exception as e:
            self.logger.error(f"Error executing attack step: {e}")
            return None

    def _update_system_state(self, event: SimulationEvent, profile: AttackProfile) -> None:
        """Update system state based on attack event."""
        if not self.state_manager:
            return

        try:
            # This would call state_manager.update_state() with event data
            # For now, just log
            self.logger.debug(
                f"Updated state: {event.attack_profile} from {event.source_ip}"
            )

        except Exception as e:
            self.logger.error(f"Error updating system state: {e}")

    def _select_weighted_attack(self) -> str:
        """Select an attack profile based on weighted probabilities."""
        profiles = list(self.ATTACK_WEIGHTS.keys())
        weights = list(self.ATTACK_WEIGHTS.values())
        return random.choices(profiles, weights=weights, k=1)[0]

    def _generate_attacker_ip(self) -> str:
        """Generate a random attacker IP address."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _generate_target_ip(self) -> str:
        """Generate a random target IP address (usually internal)."""
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def get_active_scenario(self) -> Optional[Dict[str, Any]]:
        """Get details about the currently active scenario."""
        if not self.active_scenario or not self.scenario_start_time:
            return None

        elapsed = (datetime.utcnow() - self.scenario_start_time).total_seconds()

        return {
            "profile": self.active_scenario,
            "started_at": self.scenario_start_time.isoformat(),
            "duration": self.scenario_duration,
            "elapsed": int(elapsed),
            "remaining": max(0, int(self.scenario_duration - elapsed)),
            "progress": min(100, int(elapsed / self.scenario_duration * 100)),
        }

    def get_simulation_statistics(self) -> Dict[str, Any]:
        """Get overall simulation statistics."""
        total_events = len(self.events_generated)

        return {
            "total_events_generated": total_events,
            "is_running": self.is_running,
            "active_scenario": self.active_scenario,
            "events_by_attack_type": self.attack_counts.copy(),
            "total_attacks_simulated": sum(self.attack_counts.values()),
            "average_event_severity": (
                sum(
                    ATTACK_PROFILES[name].severity * count
                    for name, count in self.attack_counts.items()
                ) / max(1, sum(self.attack_counts.values()))
            ),
        }

    def get_recent_events(self, n: int = 20) -> List[Dict[str, Any]]:
        """Get the most recent N simulation events."""
        recent = self.events_generated[-n:]
        return [asdict(event) for event in recent]

    def clear_events(self) -> None:
        """Clear all generated events from history."""
        self.events_generated.clear()
        self.logger.info("Cleared event history")

    def reset_statistics(self) -> None:
        """Reset all statistics."""
        for key in self.attack_counts:
            self.attack_counts[key] = 0
        self.logger.info("Reset attack statistics")

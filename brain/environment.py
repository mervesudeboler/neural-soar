"""
SOAR Reinforcement Learning Environment
Custom Gym environment for training security response agents.
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces
from typing import Tuple, Dict, Optional, Any
import logging
from enum import IntEnum
import random
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ActionType(IntEnum):
    """Action enum for SOAR responses."""
    MONITOR = 0
    RATE_LIMIT = 1
    BLOCK_IP = 2
    REDIRECT_HONEYPOT = 3
    ISOLATE_CONTAINER = 4


class AttackType(IntEnum):
    """Attack type enum for scenarios."""
    NORMAL = 0
    DDOS = 1
    PORT_SCAN = 2
    BRUTE_FORCE = 3
    MALWARE = 4
    LATERAL_MOVEMENT = 5
    HIGH_LOAD = 6


class SimulatedStateManager:
    """Fallback simulated state manager if real one not available."""
    
    def __init__(self):
        self.cpu_load = 0.3
        self.open_ports = 10
        self.alert_severity = 0.2
        self.active_connections = 50
        self.attack_type = AttackType.NORMAL
        self.trust_score = 0.9
        self.honeypot_active = False
        self.banned_ips = 0
        self.failed_login_rate = 0.05
        self.connection_rate = 100
        self.system_uptime = 30.0  # days
        self.threat_level = 0.1
        
    def get_state(self) -> Dict[str, Any]:
        """Get current system state."""
        return {
            "cpu_load": self.cpu_load,
            "open_ports": self.open_ports,
            "alert_severity": self.alert_severity,
            "active_connections": self.active_connections,
            "attack_type": self.attack_type,
            "trust_score": self.trust_score,
            "honeypot_active": self.honeypot_active,
            "banned_ips": self.banned_ips,
            "failed_login_rate": self.failed_login_rate,
            "connection_rate": self.connection_rate,
            "system_uptime": self.system_uptime,
            "threat_level": self.threat_level
        }


class SOAREnvironment(gym.Env):
    """
    Custom OpenAI Gym environment for SOAR RL training.
    """
    
    metadata = {"render_modes": ["human"]}
    MAX_STEPS = 200
    
    def __init__(self, state_manager: Optional[SimulatedStateManager] = None):
        """
        Initialize SOAR environment.
        
        Args:
            state_manager: Optional state manager (uses SimulatedStateManager if None)
        """
        super().__init__()
        
        # Use provided state manager or create simulated one
        self.state_manager = state_manager or SimulatedStateManager()
        
        # Define observation and action spaces
        self.observation_space = spaces.Box(
            low=0, 
            high=1, 
            shape=(12,), 
            dtype=np.float32
        )
        
        self.action_space = spaces.Discrete(5)
        
        # Initialize state tracking
        self.current_observation = np.zeros(12, dtype=np.float32)
        self.episode_reward = 0.0
        self.step_count = 0
        self.attack_history = []
        self.action_history = []
        self.response_times = []
        self.previous_uptime = 30.0
        self.last_attack_type = AttackType.NORMAL
        
        # Action name mapping
        self.action_names = {
            ActionType.MONITOR: "MONITOR",
            ActionType.RATE_LIMIT: "RATE_LIMIT",
            ActionType.BLOCK_IP: "BLOCK_IP",
            ActionType.REDIRECT_HONEYPOT: "REDIRECT_HONEYPOT",
            ActionType.ISOLATE_CONTAINER: "ISOLATE_CONTAINER"
        }
        
        logger.info("SOAR Environment initialized")
    
    def reset(self, seed: Optional[int] = None, **kwargs) -> Tuple[np.ndarray, Dict]:
        """
        Reset environment to initial state.
        
        Args:
            seed: Random seed for reproducibility
            **kwargs: Additional gymnasium reset kwargs
            
        Returns:
            Tuple of initial observation and info dict
        """
        super().reset(seed=seed)
        
        # Reset tracking variables
        self.episode_reward = 0.0
        self.step_count = 0
        self.attack_history = []
        self.action_history = []
        self.response_times = []
        self.previous_uptime = 30.0
        self.last_attack_type = AttackType.NORMAL
        
        # Generate initial attack scenario
        self._generate_attack_scenario()
        
        # Get initial observation
        self.current_observation = self._get_observation()
        
        logger.info("Environment reset")
        return self.current_observation, {}
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """
        Execute one step in the environment.
        
        Args:
            action: Action to take (0-4)
            
        Returns:
            Tuple of (observation, reward, terminated, truncated, info)
        """
        start_time = datetime.now()
        self.step_count += 1
        
        # Calculate reward for this action
        reward = self._calculate_reward(action, self.last_attack_type)
        
        # Update episode reward
        self.episode_reward += reward
        
        # Track action and response time
        self.action_history.append(action)
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        self.response_times.append(response_time)
        
        # Add response time bonus/penalty
        if response_time < 100:
            reward += 0.2
        else:
            reward += max(-0.3, -response_time / 1000)
        
        # Simulate system uptime change
        self._update_system_state(action)
        
        # Check for uptime drop penalty
        current_uptime = self.state_manager.get_state()["system_uptime"]
        if current_uptime < self.previous_uptime:
            reward -= 0.5
        self.previous_uptime = current_uptime
        
        # Generate next attack scenario
        if random.random() < 0.3:  # 30% chance of new attack
            self._generate_attack_scenario()
        
        # Get new observation
        self.current_observation = self._get_observation()
        
        # Check termination conditions
        terminated = self.step_count >= self.MAX_STEPS
        truncated = False
        
        # Create info dict
        info = {
            "episode_reward": self.episode_reward,
            "step_count": self.step_count,
            "action": action,
            "action_name": self.action_names[action],
            "response_time_ms": response_time,
            "attack_type": self.last_attack_type,
            "reward": reward
        }
        
        return self.current_observation, reward, terminated, truncated, info
    
    def render(self, mode: str = "human") -> Optional[str]:
        """
        Render current environment state.
        
        Args:
            mode: Render mode ('human' for print)
            
        Returns:
            String representation if mode != 'human'
        """
        state = self.state_manager.get_state()
        
        output = []
        output.append("\n" + "="*60)
        output.append("SOAR Environment State")
        output.append("="*60)
        output.append(f"Step: {self.step_count}/{self.MAX_STEPS}")
        output.append(f"Episode Reward: {self.episode_reward:.3f}")
        output.append(f"\nSystem Metrics:")
        output.append(f"  CPU Load: {state['cpu_load']:.2%}")
        output.append(f"  Open Ports: {state['open_ports']}")
        output.append(f"  Alert Severity: {state['alert_severity']:.2%}")
        output.append(f"  Active Connections: {state['active_connections']}")
        output.append(f"  Attack Type: {AttackType(state['attack_type']).name}")
        output.append(f"  Trust Score: {state['trust_score']:.2%}")
        output.append(f"  Honeypot Active: {bool(state['honeypot_active'])}")
        output.append(f"  Banned IPs: {state['banned_ips']}")
        output.append(f"  Failed Login Rate: {state['failed_login_rate']:.2%}")
        output.append(f"  Connection Rate: {state['connection_rate']}")
        output.append(f"  System Uptime: {state['system_uptime']:.1f} days")
        output.append(f"  Threat Level: {state['threat_level']:.2%}")
        
        if self.action_history:
            output.append(f"\nLast Action: {self.action_names[self.action_history[-1]]}")
            output.append(f"Avg Response Time: {np.mean(self.response_times):.2f}ms")
        
        output.append("="*60 + "\n")
        
        print("\n".join(output))
        return "\n".join(output)
    
    def _get_observation(self) -> np.ndarray:
        """
        Get normalized observation vector from current state.
        
        Returns:
            Normalized observation array of shape (12,)
        """
        state = self.state_manager.get_state()
        
        observation = np.array([
            state["cpu_load"],  # 0: normalized (0-1)
            state["open_ports"] / 65535.0,  # 1: normalized
            state["alert_severity"],  # 2: normalized (0-1)
            state["active_connections"] / 10000.0,  # 3: normalized
            state["attack_type"] / 6.0,  # 4: attack type encoded (0-1)
            state["trust_score"],  # 5: normalized (0-1)
            float(state["honeypot_active"]),  # 6: binary (0/1)
            state["banned_ips"] / 10000.0,  # 7: normalized
            state["failed_login_rate"],  # 8: normalized (0-1)
            state["connection_rate"] / 10000.0,  # 9: normalized
            min(state["system_uptime"] / 365.0, 1.0),  # 10: normalized (0-1)
            state["threat_level"]  # 11: threat level encoded (0-1)
        ], dtype=np.float32)
        
        return np.clip(observation, 0, 1)
    
    def _generate_attack_scenario(self) -> None:
        """
        Generate a realistic attack scenario for the environment.
        Simulates various security threats with appropriate state changes.
        """
        scenario_type = random.randint(0, 6)
        
        if scenario_type == 0:  # Normal operation
            self.last_attack_type = AttackType.NORMAL
            self.state_manager.cpu_load = random.uniform(0.1, 0.4)
            self.state_manager.alert_severity = random.uniform(0.0, 0.1)
            self.state_manager.open_ports = random.randint(5, 20)
            self.state_manager.active_connections = random.randint(30, 100)
            self.state_manager.threat_level = random.uniform(0.0, 0.1)
            self.state_manager.failed_login_rate = random.uniform(0.01, 0.05)
            
        elif scenario_type == 1:  # DDoS Attack
            self.last_attack_type = AttackType.DDOS
            self.state_manager.cpu_load = random.uniform(0.7, 0.95)
            self.state_manager.alert_severity = random.uniform(0.7, 0.95)
            self.state_manager.active_connections = random.randint(5000, 10000)
            self.state_manager.connection_rate = random.randint(5000, 20000)
            self.state_manager.threat_level = 0.9
            
        elif scenario_type == 2:  # Port Scan
            self.last_attack_type = AttackType.PORT_SCAN
            self.state_manager.open_ports = random.randint(50, 200)
            self.state_manager.alert_severity = random.uniform(0.4, 0.7)
            self.state_manager.threat_level = random.uniform(0.5, 0.7)
            self.state_manager.active_connections = random.randint(100, 500)
            
        elif scenario_type == 3:  # Brute Force
            self.last_attack_type = AttackType.BRUTE_FORCE
            self.state_manager.failed_login_rate = random.uniform(0.5, 0.95)
            self.state_manager.alert_severity = random.uniform(0.6, 0.85)
            self.state_manager.threat_level = random.uniform(0.6, 0.8)
            self.state_manager.active_connections = random.randint(200, 1000)
            
        elif scenario_type == 4:  # Malware
            self.last_attack_type = AttackType.MALWARE
            self.state_manager.cpu_load = random.uniform(0.6, 0.9)
            self.state_manager.alert_severity = random.uniform(0.8, 1.0)
            self.state_manager.threat_level = 0.95
            self.state_manager.trust_score = random.uniform(0.2, 0.5)
            
        elif scenario_type == 5:  # Lateral Movement
            self.last_attack_type = AttackType.LATERAL_MOVEMENT
            self.state_manager.active_connections = random.randint(500, 2000)
            self.state_manager.alert_severity = random.uniform(0.6, 0.85)
            self.state_manager.threat_level = random.uniform(0.7, 0.9)
            self.state_manager.trust_score = random.uniform(0.3, 0.6)
            
        else:  # High Load
            self.last_attack_type = AttackType.HIGH_LOAD
            self.state_manager.cpu_load = random.uniform(0.5, 0.8)
            self.state_manager.active_connections = random.randint(2000, 5000)
            self.state_manager.connection_rate = random.randint(2000, 5000)
            self.state_manager.alert_severity = random.uniform(0.4, 0.6)
        
        self.attack_history.append(self.last_attack_type)
    
    def _calculate_reward(self, action: int, attack_type: int) -> float:
        """
        Calculate reward for an action given the current attack type.
        
        Args:
            action: Action taken (0-4)
            attack_type: Current attack type (0-6)
            
        Returns:
            Reward value
        """
        action_enum = ActionType(action)
        attack_enum = AttackType(attack_type)
        
        reward = 0.0
        
        if action_enum == ActionType.MONITOR:
            if attack_enum == AttackType.NORMAL:
                reward = 0.1
            else:
                reward = -2.0
                
        elif action_enum == ActionType.RATE_LIMIT:
            if attack_enum in [AttackType.DDOS, AttackType.HIGH_LOAD]:
                reward = 0.8
            elif attack_enum == AttackType.NORMAL:
                reward = -0.3
            else:
                reward = 0.2
                
        elif action_enum == ActionType.BLOCK_IP:
            if attack_enum in [AttackType.PORT_SCAN, AttackType.BRUTE_FORCE]:
                reward = 1.5
            elif attack_enum == AttackType.NORMAL:
                reward = -0.5
            else:
                reward = 0.4
                
        elif action_enum == ActionType.REDIRECT_HONEYPOT:
            if attack_enum == AttackType.NORMAL:
                reward = -0.8
            else:
                reward = 2.0
                
        elif action_enum == ActionType.ISOLATE_CONTAINER:
            if attack_enum in [AttackType.MALWARE, AttackType.LATERAL_MOVEMENT]:
                reward = 1.8
            elif attack_enum == AttackType.NORMAL:
                reward = -1.0
            else:
                reward = 0.3
        
        return reward
    
    def _update_system_state(self, action: int) -> None:
        """
        Update system state based on action taken.
        Simulates the effects of security responses.
        
        Args:
            action: Action taken
        """
        action_enum = ActionType(action)
        
        if action_enum == ActionType.BLOCK_IP:
            self.state_manager.banned_ips = min(
                self.state_manager.banned_ips + random.randint(1, 5),
                10000
            )
            
        elif action_enum == ActionType.RATE_LIMIT:
            self.state_manager.active_connections = max(
                self.state_manager.active_connections * 0.7,
                10
            )
            self.state_manager.cpu_load *= 0.85
            
        elif action_enum == ActionType.ISOLATE_CONTAINER:
            self.state_manager.cpu_load = max(self.state_manager.cpu_load * 0.6, 0.1)
            self.state_manager.active_connections = max(
                self.state_manager.active_connections * 0.5,
                5
            )
            
        elif action_enum == ActionType.REDIRECT_HONEYPOT:
            self.state_manager.honeypot_active = True
            
        # Random small degradation over time
        self.state_manager.system_uptime = max(
            self.state_manager.system_uptime - random.uniform(0.001, 0.01),
            0.0
        )
        
        # Slight threat level decay over time
        self.state_manager.threat_level = max(
            self.state_manager.threat_level * 0.95,
            0.0
        )

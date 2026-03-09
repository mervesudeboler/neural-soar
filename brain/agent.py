"""
SOAR Reinforcement Learning Agent
Wraps Stable Baselines3 PPO for security response training.
"""

import numpy as np
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
import logging
from dataclasses import dataclass
import json
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class RuleBasedAction:
    """Result from rule-based fallback agent."""
    action: int
    action_name: str
    confidence: float


class RuleBasedAgent:
    """
    Fallback rule-based agent when Stable Baselines3 is unavailable.
    Uses simple if-else rules to make security decisions.
    """
    
    def __init__(self):
        """Initialize rule-based agent."""
        self.action_names = {
            0: "MONITOR",
            1: "RATE_LIMIT",
            2: "BLOCK_IP",
            3: "REDIRECT_HONEYPOT",
            4: "ISOLATE_CONTAINER"
        }
        logger.info("RuleBasedAgent initialized as fallback")
    
    def predict(self, observation: np.ndarray) -> Tuple[int, np.ndarray]:
        """
        Predict action using rule-based logic.
        
        Args:
            observation: Observation vector of shape (12,)
            
        Returns:
            Tuple of (action, action_probabilities)
        """
        # Extract observation components
        cpu_load = observation[0]
        open_ports_norm = observation[1]
        alert_severity = observation[2]
        active_connections_norm = observation[3]
        attack_type_encoded = observation[4]
        trust_score = observation[5]
        honeypot_active = observation[6]
        banned_ips_norm = observation[7]
        failed_login_rate = observation[8]
        connection_rate_norm = observation[9]
        system_uptime_norm = observation[10]
        threat_level = observation[11]
        
        # Initialize action probabilities
        action_probs = np.array([0.2, 0.2, 0.2, 0.2, 0.2], dtype=np.float32)
        
        # Rule-based decision logic
        action = 0  # Default to MONITOR
        
        # High threat level - aggressive response
        if threat_level > 0.8:
            if attack_type_encoded > 0.4:  # Not normal traffic
                if failed_login_rate > 0.5:  # Brute force
                    action = 2  # BLOCK_IP
                    action_probs = np.array([0.05, 0.05, 0.8, 0.05, 0.05], dtype=np.float32)
                elif cpu_load > 0.7:  # DDoS/High load
                    action = 1  # RATE_LIMIT
                    action_probs = np.array([0.05, 0.8, 0.05, 0.05, 0.05], dtype=np.float32)
                else:  # Unknown attack
                    action = 3  # REDIRECT_HONEYPOT
                    action_probs = np.array([0.05, 0.05, 0.05, 0.8, 0.05], dtype=np.float32)
        
        # Medium threat level - moderate response
        elif threat_level > 0.5:
            if failed_login_rate > 0.3:
                action = 2  # BLOCK_IP
                action_probs = np.array([0.1, 0.1, 0.6, 0.1, 0.1], dtype=np.float32)
            elif cpu_load > 0.6:
                action = 1  # RATE_LIMIT
                action_probs = np.array([0.1, 0.6, 0.1, 0.1, 0.1], dtype=np.float32)
            elif trust_score < 0.3:
                action = 3  # REDIRECT_HONEYPOT
                action_probs = np.array([0.1, 0.1, 0.1, 0.6, 0.1], dtype=np.float32)
            else:
                action = 0  # MONITOR
                action_probs = np.array([0.6, 0.1, 0.1, 0.1, 0.1], dtype=np.float32)
        
        # Low threat level - passive monitoring
        else:
            action = 0  # MONITOR
            action_probs = np.array([0.7, 0.1, 0.05, 0.1, 0.05], dtype=np.float32)
        
        return action, action_probs
    
    def save(self, path: str) -> None:
        """Save agent state (rule-based has no state to save)."""
        logger.info(f"RuleBasedAgent save requested to {path} (no-op)")
    
    def load(self, path: str) -> None:
        """Load agent state (rule-based has no state to load)."""
        logger.info(f"RuleBasedAgent load requested from {path} (no-op)")


class SOARAgent:
    """
    SOAR Reinforcement Learning Agent using PPO from Stable Baselines3.
    Learns optimal security response strategies.
    """
    
    def __init__(self, env, use_rule_based: bool = False):
        """
        Initialize SOAR Agent.
        
        Args:
            env: Gymnasium environment
            use_rule_based: Force use of rule-based fallback if True
        """
        self.env = env
        self.model = None
        self.use_rule_based = use_rule_based
        self.checkpoint_counter = 0
        
        # Action name mapping
        self.action_names = {
            0: "MONITOR",
            1: "RATE_LIMIT",
            2: "BLOCK_IP",
            3: "REDIRECT_HONEYPOT",
            4: "ISOLATE_CONTAINER"
        }
        
        # Hyperparameters
        self.hyperparams = {
            "learning_rate": 3e-4,
            "n_steps": 2048,
            "batch_size": 64,
            "n_epochs": 10,
            "gamma": 0.99,
            "gae_lambda": 0.95
        }
        
        # Try to initialize PPO, fall back to rule-based
        if not use_rule_based:
            self._init_ppo()
        else:
            self.model = RuleBasedAgent()
            logger.info("Using RuleBasedAgent")
    
    def _init_ppo(self) -> None:
        """Initialize PPO model from Stable Baselines3."""
        try:
            from stable_baselines3 import PPO

            # Create logs directory
            logs_dir = Path("./logs/tensorboard")
            logs_dir.mkdir(parents=True, exist_ok=True)

            self.model = PPO(
                "MlpPolicy",
                self.env,
                learning_rate=self.hyperparams["learning_rate"],
                n_steps=self.hyperparams["n_steps"],
                batch_size=self.hyperparams["batch_size"],
                n_epochs=self.hyperparams["n_epochs"],
                gamma=self.hyperparams["gamma"],
                gae_lambda=self.hyperparams["gae_lambda"],
                tensorboard_log="./logs/tensorboard",
                policy_kwargs={"net_arch": [256, 256, 128]},
                verbose=1
            )
            logger.info("PPO agent initialized successfully")

        except ImportError:
            logger.warning("Stable Baselines3 not available, using RuleBasedAgent fallback")
            self.model = RuleBasedAgent()
            self.use_rule_based = True
    
    def train(self, env, total_timesteps: int = 100000) -> None:
        """
        Train the RL agent.
        
        Args:
            env: Training environment
            total_timesteps: Total training timesteps
        """
        if self.use_rule_based or isinstance(self.model, RuleBasedAgent):
            logger.warning("Cannot train RuleBasedAgent, skipping training")
            return
        
        logger.info(f"Starting training for {total_timesteps} timesteps")
        
        try:
            self.model.learn(
                total_timesteps=total_timesteps,
                log_interval=10,
                progress_bar=True
            )
            logger.info("Training completed successfully")
        except Exception as e:
            logger.error(f"Training failed: {e}")
            raise
    
    def predict(self, observation: np.ndarray) -> Tuple[int, np.ndarray]:
        """
        Predict action for given observation.
        
        Args:
            observation: Observation vector of shape (12,)
            
        Returns:
            Tuple of (action, action_probabilities)
        """
        if isinstance(self.model, RuleBasedAgent):
            action, probs = self.model.predict(observation)
            return action, probs
        
        try:
            action, _ = self.model.predict(observation, deterministic=False)
            
            # Try to get action probabilities from policy
            action_probs = self._get_action_probabilities(observation)
            
            return int(action), action_probs
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}, using rule-based fallback")
            return self._fallback_predict(observation)
    
    def _get_action_probabilities(self, observation: np.ndarray) -> np.ndarray:
        """
        Get action probability distribution from policy.
        
        Args:
            observation: Observation vector
            
        Returns:
            Action probability array
        """
        try:
            if hasattr(self.model, "policy"):
                obs_tensor = self.model.policy.obs_to_tensor(observation)
                with self.model.policy.set_training_mode(False):
                    distribution = self.model.policy.get_distribution(obs_tensor[0])
                    probs = distribution.distribution.probs.detach().cpu().numpy()[0]
                    return probs.astype(np.float32)
        except Exception:
            pass
        
        # Default: equal probability
        return np.array([0.2, 0.2, 0.2, 0.2, 0.2], dtype=np.float32)
    
    def _fallback_predict(self, observation: np.ndarray) -> Tuple[int, np.ndarray]:
        """
        Fallback prediction using simple rules.
        
        Args:
            observation: Observation vector
            
        Returns:
            Tuple of (action, action_probabilities)
        """
        threat_level = observation[11]
        
        if threat_level > 0.8:
            action = np.random.choice([1, 2, 3, 4])
        elif threat_level > 0.5:
            action = np.random.choice([1, 2, 3])
        else:
            action = 0
        
        probs = np.zeros(5, dtype=np.float32)
        probs[action] = 1.0
        
        return action, probs
    
    def save(self, path: str) -> None:
        """
        Save agent model and metadata.
        
        Args:
            path: Path to save model
        """
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        if isinstance(self.model, RuleBasedAgent):
            logger.info("RuleBasedAgent has no model to save")
            return
        
        try:
            model_path = path / "model"
            self.model.save(str(model_path))
            
            # Save metadata
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "hyperparams": self.hyperparams,
                "model_type": "PPO"
            }
            
            metadata_path = path / "metadata.json"
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Model saved to {path}")
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def load(self, path: str) -> None:
        """
        Load agent model and metadata.
        
        Args:
            path: Path to load model from
        """
        path = Path(path)
        
        if isinstance(self.model, RuleBasedAgent):
            logger.info("RuleBasedAgent has no model to load")
            return
        
        try:
            from stable_baselines3 import PPO
            
            model_path = path / "model"
            self.model = PPO.load(str(model_path), env=self.env)
            
            # Load metadata
            metadata_path = path / "metadata.json"
            if metadata_path.exists():
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
                    logger.info(f"Loaded metadata: {metadata}")
            
            logger.info(f"Model loaded from {path}")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def get_action_name(self, action_id: int) -> str:
        """
        Get human-readable action name.
        
        Args:
            action_id: Action ID (0-4)
            
        Returns:
            Action name string
        """
        return self.action_names.get(action_id, "UNKNOWN")
    
    def save_checkpoint(self, checkpoint_dir: str = "./checkpoints") -> None:
        """
        Save model checkpoint with numbered suffix.
        
        Args:
            checkpoint_dir: Directory to save checkpoints
        """
        if isinstance(self.model, RuleBasedAgent):
            return
        
        try:
            checkpoint_path = Path(checkpoint_dir)
            checkpoint_path.mkdir(parents=True, exist_ok=True)
            
            checkpoint_file = checkpoint_path / f"checkpoint_{self.checkpoint_counter:06d}"
            self.model.save(str(checkpoint_file))
            
            self.checkpoint_counter += 1
            logger.info(f"Checkpoint saved: {checkpoint_file}")
            
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")

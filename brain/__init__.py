"""
Neural SOAR - Brain Layer (The Brain)
Reinforcement Learning agent that learns optimal security response strategies.
Uses PPO (Proximal Policy Optimization) via Stable Baselines3.
"""
from .environment import SOAREnvironment
from .agent import SOARAgent
from .train import SOARTrainer
from .inference import SOARInference

__all__ = ["SOAREnvironment", "SOARAgent", "SOARTrainer", "SOARInference"]

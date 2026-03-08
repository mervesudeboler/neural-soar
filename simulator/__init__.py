"""
Neural SOAR - Attack Simulator
Generates realistic attack scenarios for training and testing the RL agent.
"""
from .attack_simulator import AttackSimulator
from .attack_profiles import AttackProfile, ATTACK_PROFILES

__all__ = ["AttackSimulator", "AttackProfile", "ATTACK_PROFILES"]

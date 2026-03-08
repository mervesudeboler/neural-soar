"""
Neural SOAR - Hands Layer (The Hands)
Executes defensive actions decided by the RL agent.
In simulation mode: logs actions and updates state.
In production mode: interacts with iptables, Docker, Kubernetes.
"""
from .action_engine import ActionEngine
from .firewall import FirewallManager
from .honeypot import HoneypotManager
from .container_isolator import ContainerIsolator

__all__ = ["ActionEngine", "FirewallManager", "HoneypotManager", "ContainerIsolator"]

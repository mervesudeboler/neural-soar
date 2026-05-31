"""
Neural SOAR - Eyes Layer (The Eyes)
Real-time dashboard showing event flow, attack types, and autonomous actions taken.
Built with Flask + WebSocket for live updates.
"""
from .dashboard import create_app, SOARDashboard

__all__ = ["create_app", "SOARDashboard"]

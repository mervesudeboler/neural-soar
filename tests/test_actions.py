"""
Unit tests for ActionEngine, FirewallManager, and HoneypotManager.
Uses correct import paths: hands.action_engine, hands.firewall, hands.honeypot
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime
from hands.action_engine import ActionEngine, ActionResult, ActionType
from hands.firewall import FirewallManager
from hands.honeypot import HoneypotManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def firewall():
    """FirewallManager in simulation mode."""
    return FirewallManager(simulation_mode=True)


@pytest.fixture
def honeypot():
    """HoneypotManager in simulation mode."""
    return HoneypotManager(simulation_mode=True)


@pytest.fixture
def engine(firewall, honeypot):
    """ActionEngine wired with FirewallManager and HoneypotManager."""
    return ActionEngine(
        firewall_manager=firewall,
        honeypot_manager=honeypot,
        simulation_mode=True,
    )


@pytest.fixture
def bare_engine():
    """ActionEngine without sub-managers (tests graceful failure paths)."""
    return ActionEngine(simulation_mode=True)


# ---------------------------------------------------------------------------
# ActionType enum
# ---------------------------------------------------------------------------

class TestActionTypeEnum:
    """Sanity-check the ActionType enum values."""

    def test_action_ids(self):
        assert ActionType.MONITOR.value == 0
        assert ActionType.RATE_LIMIT.value == 1
        assert ActionType.BLOCK_IP.value == 2
        assert ActionType.REDIRECT_HONEYPOT.value == 3
        assert ActionType.ISOLATE_CONTAINER.value == 4

    def test_five_actions_exist(self):
        assert len(ActionType) == 5


# ---------------------------------------------------------------------------
# ActionEngine initialisation
# ---------------------------------------------------------------------------

class TestActionEngineInit:
    """Test ActionEngine initial state."""

    def test_simulation_mode_flag(self, engine):
        assert engine.simulation_mode is True

    def test_empty_history_on_init(self, engine):
        assert len(engine.action_history) == 0

    def test_zero_action_counts(self, engine):
        for name in ["MONITOR", "RATE_LIMIT", "BLOCK_IP", "REDIRECT_HONEYPOT", "ISOLATE_CONTAINER"]:
            assert engine.action_counts[name] == 0


# ---------------------------------------------------------------------------
# execute_action — monitor
# ---------------------------------------------------------------------------

class TestMonitorAction:
    """Tests for MONITOR action (action_id=0)."""

    def test_monitor_returns_action_result(self, engine):
        result = engine.execute_action(0, {"target_ip": "10.0.0.1"})
        assert isinstance(result, ActionResult)

    def test_monitor_succeeds(self, engine):
        result = engine.execute_action(0, {"target_ip": "10.0.0.1"})
        assert result.success is True

    def test_monitor_action_name(self, engine):
        result = engine.execute_action(0, {"target_ip": "10.0.0.1"})
        assert result.action_name == "MONITOR"

    def test_monitor_recorded_in_history(self, engine):
        engine.execute_action(0, {"target_ip": "10.0.0.2"})
        assert len(engine.action_history) == 1
        assert engine.action_history[0].action_name == "MONITOR"

    def test_monitor_has_timestamp(self, engine):
        result = engine.execute_action(0, {"target_ip": "10.0.0.3"})
        assert isinstance(result.timestamp, datetime)

    def test_monitor_execution_time_recorded(self, engine):
        result = engine.execute_action(0, {"target_ip": "10.0.0.4"})
        assert result.execution_time_ms >= 0


# ---------------------------------------------------------------------------
# execute_action — block IP (via FirewallManager)
# ---------------------------------------------------------------------------

class TestBlockIPAction:
    """Tests for BLOCK_IP action (action_id=2)."""

    def test_block_ip_succeeds(self, engine):
        result = engine.execute_action(2, {"target_ip": "1.2.3.4", "duration": 3600})
        assert result.success is True

    def test_block_ip_action_name(self, engine):
        result = engine.execute_action(2, {"target_ip": "1.2.3.5"})
        assert result.action_name == "BLOCK_IP"

    def test_block_ip_target_recorded(self, engine):
        result = engine.execute_action(2, {"target_ip": "1.2.3.6"})
        assert result.target_ip == "1.2.3.6"

    def test_block_ip_without_firewall_fails_gracefully(self, bare_engine):
        """Without a FirewallManager, BLOCK_IP should return success=False, not crash."""
        result = bare_engine.execute_action(2, {"target_ip": "9.9.9.9"})
        assert result.success is False
        assert result.action_name == "BLOCK_IP"

    def test_block_ip_increments_count(self, engine):
        engine.execute_action(2, {"target_ip": "2.2.2.2"})
        assert engine.action_counts["BLOCK_IP"] == 1


# ---------------------------------------------------------------------------
# execute_action — rate limit
# ---------------------------------------------------------------------------

class TestRateLimitAction:
    """Tests for RATE_LIMIT action (action_id=1)."""

    def test_rate_limit_succeeds(self, engine):
        result = engine.execute_action(1, {"target_ip": "3.3.3.3"})
        assert result.success is True

    def test_rate_limit_action_name(self, engine):
        result = engine.execute_action(1, {"target_ip": "3.3.3.4"})
        assert result.action_name == "RATE_LIMIT"

    def test_rate_limit_increments_count(self, engine):
        engine.execute_action(1, {"target_ip": "3.3.3.5"})
        assert engine.action_counts["RATE_LIMIT"] == 1


# ---------------------------------------------------------------------------
# execute_action — honeypot redirect
# ---------------------------------------------------------------------------

class TestHoneypotAction:
    """Tests for REDIRECT_HONEYPOT action (action_id=3)."""

    def test_honeypot_action_name(self, engine):
        result = engine.execute_action(3, {"target_ip": "4.4.4.4", "service_type": "ssh"})
        assert result.action_name == "REDIRECT_HONEYPOT"

    def test_honeypot_without_manager_fails_gracefully(self, bare_engine):
        """Without HoneypotManager, action should fail gracefully."""
        result = bare_engine.execute_action(3, {"target_ip": "5.5.5.5"})
        assert result.success is False
        assert result.action_name == "REDIRECT_HONEYPOT"

    def test_honeypot_increments_count(self, engine):
        engine.execute_action(3, {"target_ip": "4.4.4.5", "service_type": "http"})
        assert engine.action_counts["REDIRECT_HONEYPOT"] == 1


# ---------------------------------------------------------------------------
# execute_action — container isolate
# ---------------------------------------------------------------------------

class TestContainerIsolateAction:
    """Tests for ISOLATE_CONTAINER action (action_id=4)."""

    def test_isolate_without_manager_fails_gracefully(self, bare_engine):
        """Without ContainerIsolator, action should fail gracefully, not crash."""
        result = bare_engine.execute_action(4, {"container_id": "abc123"})
        assert result.success is False
        assert result.action_name == "ISOLATE_CONTAINER"

    def test_isolate_increments_count(self, bare_engine):
        bare_engine.execute_action(4, {"container_id": "abc123"})
        assert bare_engine.action_counts["ISOLATE_CONTAINER"] == 1


# ---------------------------------------------------------------------------
# Invalid action
# ---------------------------------------------------------------------------

class TestInvalidAction:
    """Tests for invalid action IDs."""

    def test_invalid_action_returns_failure(self, engine):
        result = engine.execute_action(99, {"target_ip": "0.0.0.0"})
        assert result.success is False

    def test_invalid_action_does_not_crash(self, engine):
        try:
            engine.execute_action(-1, {})
        except Exception as e:
            pytest.fail(f"execute_action(-1) raised an exception: {e}")


# ---------------------------------------------------------------------------
# History and statistics
# ---------------------------------------------------------------------------

class TestHistoryAndStatistics:
    """Test history tracking and statistics reporting."""

    def test_history_grows_with_each_action(self, engine):
        for i in range(5):
            engine.execute_action(0, {"target_ip": f"10.0.{i}.1"})
        assert len(engine.action_history) == 5

    def test_action_counts_all_types(self, engine):
        contexts = [
            {"target_ip": "10.1.1.1"},
            {"target_ip": "10.1.1.2"},
            {"target_ip": "10.1.1.3", "duration": 3600},
            {"target_ip": "10.1.1.4", "service_type": "ssh"},
            {"container_id": "ctr-001"},
        ]
        for action_id, ctx in enumerate(contexts):
            engine.execute_action(action_id, ctx)

        assert engine.action_counts["MONITOR"] == 1
        assert engine.action_counts["RATE_LIMIT"] == 1
        assert engine.action_counts["BLOCK_IP"] == 1
        assert engine.action_counts["REDIRECT_HONEYPOT"] == 1
        assert engine.action_counts["ISOLATE_CONTAINER"] == 1

    def test_get_action_statistics_keys(self, engine):
        engine.execute_action(0, {"target_ip": "10.2.2.2"})
        stats = engine.get_action_statistics()
        assert "total_actions" in stats
        assert "actions_by_type" in stats
        assert "success_rate" in stats

    def test_get_recent_actions_default(self, engine):
        for i in range(15):
            engine.execute_action(0, {"target_ip": f"10.3.{i}.1"})
        recent = engine.get_recent_actions()
        assert len(recent) == 10  # default n=10

    def test_get_recent_actions_custom_n(self, engine):
        for i in range(8):
            engine.execute_action(0, {"target_ip": f"10.4.{i}.1"})
        recent = engine.get_recent_actions(n=5)
        assert len(recent) == 5

    def test_clear_history(self, engine):
        engine.execute_action(0, {"target_ip": "10.5.5.5"})
        assert len(engine.action_history) == 1
        engine.clear_history()
        assert len(engine.action_history) == 0

    def test_reset_statistics(self, engine):
        engine.execute_action(0, {"target_ip": "10.6.6.6"})
        engine.reset_statistics()
        assert engine.action_counts["MONITOR"] == 0
        assert engine.action_success_counts["MONITOR"] == 0


# ---------------------------------------------------------------------------
# FirewallManager (direct tests)
# ---------------------------------------------------------------------------

class TestFirewallManager:
    """Direct tests for FirewallManager in simulation mode."""

    def test_block_returns_true(self, firewall):
        assert firewall.block_ip("11.0.0.1", 3600) is True

    def test_blocked_ip_is_tracked(self, firewall):
        firewall.block_ip("11.0.0.2", 3600)
        assert firewall.is_ip_blocked("11.0.0.2")

    def test_unblocked_ip_not_blocked(self, firewall):
        assert not firewall.is_ip_blocked("11.0.0.99")

    def test_unblock_removes_ip(self, firewall):
        firewall.block_ip("11.0.0.3", 3600)
        assert firewall.is_ip_blocked("11.0.0.3")
        firewall.unblock_ip("11.0.0.3")
        assert not firewall.is_ip_blocked("11.0.0.3")

    def test_get_blocked_ips_list(self, firewall):
        for i in range(3):
            firewall.block_ip(f"11.0.1.{i}", 3600)
        blocked = firewall.get_blocked_ips()
        assert len(blocked) >= 3


# ---------------------------------------------------------------------------
# HoneypotManager (direct tests)
# ---------------------------------------------------------------------------

class TestHoneypotManager:
    """Direct tests for HoneypotManager in simulation mode."""

    def test_create_honeypot_returns_object(self, honeypot):
        hp = honeypot.create_honeypot("12.0.0.1", "ssh")
        assert hp is not None

    def test_created_honeypot_has_id(self, honeypot):
        hp = honeypot.create_honeypot("12.0.0.2", "http")
        assert hp.id is not None and hp.id != ""

    def test_multiple_honeypots_tracked(self, honeypot):
        for i in range(3):
            honeypot.create_honeypot(f"12.0.0.{10+i}", "ssh")
        assert len(honeypot.get_active_honeypots()) >= 3

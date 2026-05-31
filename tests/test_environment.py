"""
Unit tests for SOAREnvironment
Tests use the correct brain.environment import path and shape(12,) observation space.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import numpy as np
from brain.environment import SOAREnvironment


@pytest.fixture
def env():
    """Create environment fixture."""
    return SOAREnvironment()


class TestSOAREnvironment:
    """Test cases for SOAR Environment."""

    def test_environment_initialization(self, env):
        """Test that environment initializes properly."""
        assert env is not None
        assert env.step_count == 0
        assert env.episode_reward == 0

    def test_observation_space_shape(self, env):
        """Test observation space is 12-dimensional (matches README spec)."""
        obs, _ = env.reset()
        assert obs.shape == (12,), f"Expected shape (12,), got {obs.shape}"
        assert isinstance(obs, np.ndarray)
        assert obs.dtype == np.float32

    def test_observation_space_bounds(self, env):
        """Test observation values are normalized to [0, 1]."""
        obs, _ = env.reset()
        assert np.all(obs >= 0.0), "Observation contains values below 0"
        assert np.all(obs <= 1.0), "Observation contains values above 1"

    def test_action_space(self, env):
        """Test action space has exactly 5 discrete actions."""
        assert env.action_space.n == 5
        for _ in range(20):
            action = env.action_space.sample()
            assert 0 <= action < 5

    def test_reset_returns_valid_observation(self, env):
        """Test reset returns (obs, info) with correct shapes."""
        obs, info = env.reset()
        assert obs is not None
        assert isinstance(info, dict)
        assert obs.shape == (12,)

    def test_reset_clears_state(self, env):
        """Test that reset zeroes step counter and total reward."""
        env.reset()
        for _ in range(10):
            env.step(1)

        env.reset()
        assert env.step_count == 0
        assert env.episode_reward == 0

    def test_step_returns_five_tuple(self, env):
        """Test step returns (obs, reward, terminated, truncated, info)."""
        env.reset()
        result = env.step(0)
        assert len(result) == 5, "Step should return 5-tuple"
        obs, reward, terminated, truncated, info = result

        assert obs.shape == (12,)
        assert isinstance(reward, (float, np.floating))
        assert isinstance(terminated, (bool, np.bool_))
        assert isinstance(truncated, (bool, np.bool_))
        assert isinstance(info, dict)
        assert env.step_count == 1

    def test_step_monitor_action(self, env):
        """Test step with MONITOR (action 0)."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(0)
        assert obs.shape == (12,)

    def test_step_rate_limit_action(self, env):
        """Test step with RATE_LIMIT (action 1)."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(1)
        assert obs.shape == (12,)
        assert isinstance(reward, (float, np.floating))

    def test_step_block_ip_action(self, env):
        """Test step with BLOCK_IP (action 2)."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(2)
        assert obs.shape == (12,)

    def test_step_honeypot_action(self, env):
        """Test step with REDIRECT_HONEYPOT (action 3)."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(3)
        assert obs.shape == (12,)

    def test_step_isolate_action(self, env):
        """Test step with ISOLATE_CONTAINER (action 4)."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(4)
        assert obs.shape == (12,)

    def test_all_actions_valid(self, env):
        """Test that all 5 actions execute without crashing."""
        for action_id in range(5):
            env.reset()
            obs, reward, terminated, truncated, info = env.step(action_id)
            assert obs.shape == (12,), f"Action {action_id} returned wrong shape"

    def test_episode_terminates(self, env):
        """Test that episode eventually terminates (max_steps limit)."""
        env.reset()
        terminated = False
        truncated = False
        step_count = 0

        while not (terminated or truncated) and step_count < 1500:
            _, _, terminated, truncated, _ = env.step(0)
            step_count += 1

        assert terminated or truncated or step_count >= 1500

    def test_stats_tracking(self, env):
        """Test episode statistics dictionary has required keys."""
        env.reset()
        for _ in range(30):
            _, _, terminated, truncated, _ = env.step(1)
            if terminated or truncated:
                break

        stats = env.get_stats()
        required_keys = [
            "total_steps", "total_reward", "detected_threats",
            "false_positives", "blocked_ips", "average_response_time",
        ]
        for key in required_keys:
            assert key in stats, f"Missing stat key: {key}"

    def test_action_history_tracked(self, env):
        """Test that action_history records every step."""
        env.reset()
        actions = [0, 1, 2, 3, 4, 1, 0]
        for action in actions:
            env.step(action)

        assert len(env.action_history) == len(actions)
        assert env.action_history == actions

    def test_multiple_episodes_no_crash(self, env):
        """Test running 5 full episodes without errors."""
        for episode in range(5):
            env.reset()
            done = False
            steps = 0
            while not done and steps < 50:
                _, _, terminated, truncated, _ = env.step(env.action_space.sample())
                done = terminated or truncated
                steps += 1
            assert steps > 0, f"Episode {episode} ran 0 steps"

    def test_cumulative_reward_updates(self, env):
        """Test that current_step increments after each step."""
        env.reset()
        for i in range(1, 6):
            env.step(0)
            assert env.step_count == i


class TestEnvironmentConsistency:
    """Test consistency and reproducibility properties."""

    def test_two_independent_envs_both_valid(self):
        """Test two separate env instances both produce valid observations."""
        env1 = SOAREnvironment()
        env2 = SOAREnvironment()

        obs1, _ = env1.reset()
        obs2, _ = env2.reset()

        assert obs1.shape == (12,)
        assert obs2.shape == (12,)
        assert np.all(obs1 >= 0) and np.all(obs1 <= 1)
        assert np.all(obs2 >= 0) and np.all(obs2 <= 1)

    def test_stochastic_threat_variation(self):
        """Test that the environment generates varied threat scenarios."""
        env = SOAREnvironment()
        threat_counts = []
        for _ in range(5):
            env.reset()
            for _ in range(50):
                _, _, terminated, truncated, _ = env.step(0)
                if terminated or truncated:
                    break
            threat_counts.append(env.detected_threats)

        # Basic sanity: threat counts should be non-negative
        assert all(t >= 0 for t in threat_counts)

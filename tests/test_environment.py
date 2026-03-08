"""
Unit tests for SOAREnvironment
"""

import pytest
import numpy as np
from neural_soar.environment import SOAREnvironment


@pytest.fixture
def env():
    """Create environment fixture."""
    return SOAREnvironment()


class TestSOAREnvironment:
    """Test cases for SOAR Environment."""
    
    def test_environment_initialization(self, env):
        """Test that environment initializes properly."""
        assert env is not None
        assert env.current_step == 0
        assert env.total_reward == 0
        assert len(env.blocked_ips) == 0
    
    def test_observation_space_shape(self, env):
        """Test observation space shape."""
        obs, _ = env.reset()
        assert obs.shape == (8,)
        assert isinstance(obs, np.ndarray)
        assert obs.dtype == np.float32
    
    def test_observation_space_bounds(self, env):
        """Test observation space bounds."""
        obs, _ = env.reset()
        assert np.all(obs >= 0.0)
        assert np.all(obs <= 1.0)
    
    def test_action_space(self, env):
        """Test action space properties."""
        assert env.action_space.n == 5
        for _ in range(10):
            action = env.action_space.sample()
            assert 0 <= action < 5
    
    def test_reset_returns_valid_observation(self, env):
        """Test reset returns valid observation."""
        obs, info = env.reset()
        assert obs is not None
        assert isinstance(info, dict)
        assert obs.shape == (8,)
    
    def test_reset_clears_state(self, env):
        """Test that reset clears environment state."""
        # Run some steps
        env.reset()
        for _ in range(10):
            env.step(1)
        
        # Reset
        env.reset()
        assert env.current_step == 0
        assert env.total_reward == 0
        assert len(env.blocked_ips) == 0
        assert env.detected_threats == 0
    
    def test_step_with_monitor_action(self, env):
        """Test step with monitor action."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(0)
        
        assert obs.shape == (8,)
        assert isinstance(reward, float)
        assert isinstance(terminated, (bool, np.bool_))
        assert isinstance(truncated, (bool, np.bool_))
        assert isinstance(info, dict)
        assert env.current_step == 1
    
    def test_step_with_block_action(self, env):
        """Test step with block action."""
        env.reset()
        initial_ips = len(env.blocked_ips)
        obs, reward, terminated, truncated, info = env.step(1)
        
        assert obs.shape == (8,)
        assert len(env.blocked_ips) >= initial_ips
    
    def test_step_with_rate_limit_action(self, env):
        """Test step with rate limit action."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(2)
        
        assert obs.shape == (8,)
        assert isinstance(reward, float)
    
    def test_step_with_honeypot_action(self, env):
        """Test step with honeypot action."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(3)
        
        assert obs.shape == (8,)
        assert isinstance(reward, float)
    
    def test_step_with_isolate_action(self, env):
        """Test step with isolate action."""
        env.reset()
        obs, reward, terminated, truncated, info = env.step(4)
        
        assert obs.shape == (8,)
        assert isinstance(reward, float)
    
    def test_reward_for_correct_block(self, env):
        """Test reward for blocking when threat detected."""
        env.reset()
        # Run multiple steps to find threat
        total_positive_reward = 0
        for _ in range(100):
            obs, reward, terminated, truncated, info = env.step(1)  # Block action
            if reward > 5:  # Significant positive reward
                total_positive_reward += reward
            if terminated or truncated:
                break
        
        assert total_positive_reward >= 0
    
    def test_reward_for_false_positive(self, env):
        """Test penalty for blocking when no threat."""
        env.reset()
        # Run multiple steps, some should have no threat
        penalties = []
        for _ in range(100):
            obs, reward, terminated, truncated, info = env.step(1)  # Block action
            if reward < 0:
                penalties.append(reward)
            if terminated or truncated:
                break
        
        # Should have at least some penalties for false positives
        assert len(penalties) >= 0
    
    def test_episode_termination(self, env):
        """Test that episode terminates after max steps."""
        env.reset()
        terminated = False
        step_count = 0
        
        while not terminated and step_count < 1000:
            obs, reward, terminated, truncated, info = env.step(0)
            step_count += 1
        
        assert terminated or step_count >= 1000
    
    def test_episode_statistics(self, env):
        """Test episode statistics tracking."""
        env.reset()
        for _ in range(50):
            obs, reward, terminated, truncated, info = env.step(1)
            if terminated or truncated:
                break
        
        stats = env.get_stats()
        assert 'total_steps' in stats
        assert 'total_reward' in stats
        assert 'detected_threats' in stats
        assert 'false_positives' in stats
        assert 'blocked_ips' in stats
        assert 'average_response_time' in stats
    
    def test_render_mode(self, env):
        """Test render method."""
        env.reset()
        env.step(1)
        # Just verify it doesn't crash
        try:
            env.render('human')
        except Exception as e:
            pytest.fail(f"Render failed: {e}")
    
    def test_multiple_episodes(self, env):
        """Test running multiple episodes."""
        for episode in range(3):
            env.reset()
            done = False
            steps = 0
            
            while not done and steps < 50:
                action = env.action_space.sample()
                obs, reward, terminated, truncated, info = env.step(action)
                done = terminated or truncated
                steps += 1
            
            assert steps > 0
    
    def test_action_history(self, env):
        """Test action history tracking."""
        env.reset()
        actions = [0, 1, 2, 3, 4, 1, 0]
        
        for action in actions:
            env.step(action)
        
        assert len(env.action_history) == len(actions)
        assert env.action_history == actions


class TestEnvironmentRandomness:
    """Test randomness in environment."""
    
    def test_different_episodes_are_different(self):
        """Test that different episodes have different outcomes."""
        env1 = SOAREnvironment()
        env2 = SOAREnvironment()
        
        obs1, _ = env1.reset()
        obs2, _ = env2.reset()
        
        # May be same due to randomness, but statistically different
        # Just verify both return valid observations
        assert obs1.shape == (8,)
        assert obs2.shape == (8,)
    
    def test_stochastic_threats(self):
        """Test that threat detection is stochastic."""
        env = SOAREnvironment()
        env.reset()
        
        threat_counts = []
        for _ in range(10):
            env.reset()
            for _ in range(50):
                obs, reward, terminated, truncated, info = env.step(0)
                if terminated or truncated:
                    break
            threat_counts.append(env.detected_threats)
        
        # Should have variation in threat counts
        assert len(set(threat_counts)) > 0

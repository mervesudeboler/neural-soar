"""
Unit tests for ActionEngine
"""

import pytest
from datetime import datetime, timedelta
from neural_soar.hands import ActionEngine


@pytest.fixture
def action_engine():
    """Create ActionEngine fixture."""
    return ActionEngine(simulation_mode=True)


class TestActionEngine:
    """Test cases for Action Engine."""
    
    def test_action_engine_initialization(self, action_engine):
        """Test ActionEngine initializes properly."""
        assert action_engine is not None
        assert action_engine.simulation_mode is True
        assert len(action_engine.action_history) == 0
        assert len(action_engine.blocked_ips) == 0
    
    def test_monitor_action(self, action_engine):
        """Test monitor action."""
        result = action_engine.execute_action(0, target_ip='192.168.1.100')
        
        assert result['action'] == 'monitor'
        assert result['success'] is True
        assert '192.168.1.100' in result['target_ip']
        assert len(action_engine.action_history) == 1
    
    def test_block_ip_action(self, action_engine):
        """Test block IP action."""
        target_ip = '192.168.1.101'
        result = action_engine.execute_action(1, target_ip=target_ip, duration=3600)
        
        assert result['action'] == 'block_ip'
        assert result['success'] is True
        assert target_ip in action_engine.blocked_ips
        assert result['expiration'] is not None
    
    def test_block_ip_expiration(self, action_engine):
        """Test blocked IP has correct expiration."""
        target_ip = '192.168.1.102'
        duration = 3600
        result = action_engine.execute_action(1, target_ip=target_ip, duration=duration)
        
        expiration = datetime.fromisoformat(result['expiration'])
        now = datetime.now()
        diff = (expiration - now).total_seconds()
        
        # Should be approximately the duration (within 5 seconds)
        assert abs(diff - duration) < 5
    
    def test_rate_limit_action(self, action_engine):
        """Test rate limit action."""
        target_ip = '192.168.1.103'
        result = action_engine.execute_action(2, target_ip=target_ip)
        
        assert result['action'] == 'rate_limit'
        assert result['success'] is True
        assert target_ip in action_engine.rate_limited_ips
    
    def test_honeypot_redirect_action(self, action_engine):
        """Test honeypot redirect action."""
        target_ip = '192.168.1.104'
        result = action_engine.execute_action(3, target_ip=target_ip)
        
        assert result['action'] == 'honeypot_redirect'
        assert result['success'] is True
        assert len(action_engine.honeypots) > 0
        assert 'honeypot_id' in result
    
    def test_container_isolate_action(self, action_engine):
        """Test container isolation action."""
        target_ip = '192.168.1.105'
        result = action_engine.execute_action(4, target_ip=target_ip)
        
        assert result['action'] == 'container_isolate'
        assert result['success'] is True
        assert 'container_id' in result
    
    def test_action_statistics(self, action_engine):
        """Test action statistics tracking."""
        # Execute various actions
        for action_id in range(5):
            action_engine.execute_action(action_id, target_ip='192.168.1.1')
        
        stats = action_engine.get_statistics()
        
        assert stats['total_actions'] == 5
        assert 'action_distribution' in stats
        assert 'blocked_ips_count' in stats
        assert 'success_rates' in stats
    
    def test_firewall_block_and_unblock(self, action_engine):
        """Test firewall block and unblock."""
        target_ip = '192.168.1.106'
        
        # Block IP
        action_engine.execute_action(1, target_ip=target_ip)
        assert target_ip in action_engine.blocked_ips
        
        # Unblock IP
        success = action_engine.unblock_ip(target_ip)
        assert success is True
        assert target_ip not in action_engine.blocked_ips
    
    def test_unblock_nonexistent_ip(self, action_engine):
        """Test unblocking IP that doesn't exist."""
        success = action_engine.unblock_ip('192.168.1.200')
        assert success is False
    
    def test_honeypot_creation(self, action_engine):
        """Test honeypot creation and tracking."""
        target_ip = '192.168.1.107'
        
        action_engine.execute_action(3, target_ip=target_ip)
        
        assert len(action_engine.honeypots) > 0
        honeypot = action_engine.honeypots[0]
        assert honeypot['source_ip'] == target_ip
        assert honeypot['honeypot_ip'] == '192.168.100.100'
    
    def test_action_history_tracking(self, action_engine):
        """Test action history is properly tracked."""
        actions = [0, 1, 2, 3, 4, 1, 0]
        
        for action_id in actions:
            action_engine.execute_action(action_id, target_ip='192.168.1.1')
        
        assert len(action_engine.action_history) == len(actions)
        for i, action_id in enumerate(actions):
            assert action_engine.action_history[i]['action'] == action_engine.ACTIONS[action_id]
    
    def test_action_success_rates(self, action_engine):
        """Test success rate tracking."""
        for i in range(10):
            action_engine.execute_action(1, target_ip=f'192.168.1.{100+i}')
        
        stats = action_engine.get_statistics()
        block_success_rate = stats['success_rates'].get('block_ip', 0)
        
        # All block actions should succeed in simulation mode
        assert block_success_rate >= 0.9
    
    def test_get_blocked_ips(self, action_engine):
        """Test getting list of blocked IPs."""
        ips = ['192.168.1.110', '192.168.1.111', '192.168.1.112']
        
        for ip in ips:
            action_engine.execute_action(1, target_ip=ip, duration=3600)
        
        blocked = action_engine.get_blocked_ips()
        assert len(blocked) == 3
        for ip in ips:
            assert ip in blocked
    
    def test_cleanup_expired_blocks(self, action_engine):
        """Test cleanup of expired blocks."""
        target_ip = '192.168.1.113'
        
        # Block with 1 second duration
        action_engine.execute_action(1, target_ip=target_ip, duration=1)
        
        # Should be blocked
        assert target_ip in action_engine.blocked_ips
        assert len(action_engine.get_blocked_ips()) == 1
        
        # Manually expire the block
        action_engine.blocked_ips[target_ip] = datetime.now() - timedelta(seconds=1)
        
        # Cleanup
        expired_count = action_engine.cleanup_expired_blocks()
        
        assert expired_count == 1
        assert target_ip not in action_engine.blocked_ips
    
    def test_action_timestamps(self, action_engine):
        """Test that actions have timestamps."""
        result = action_engine.execute_action(0, target_ip='192.168.1.120')
        
        assert 'timestamp' in result
        # Try to parse as ISO format
        timestamp = datetime.fromisoformat(result['timestamp'])
        assert timestamp is not None
    
    def test_multiple_honeypots(self, action_engine):
        """Test creating multiple honeypots."""
        for i in range(3):
            action_engine.execute_action(3, target_ip=f'192.168.1.{130+i}')
        
        assert len(action_engine.honeypots) == 3
        
        stats = action_engine.get_statistics()
        assert stats['honeypots_active'] == 3
    
    def test_rate_limited_ips_tracking(self, action_engine):
        """Test rate limited IPs are tracked."""
        for i in range(5):
            action_engine.execute_action(2, target_ip=f'192.168.1.{140+i}')
        
        stats = action_engine.get_statistics()
        assert stats['rate_limited_ips_count'] == 5


class TestActionEngineProductionMode:
    """Test ActionEngine in production mode."""
    
    def test_production_mode_initialization(self):
        """Test ActionEngine in production mode."""
        engine = ActionEngine(simulation_mode=False)
        assert engine.simulation_mode is False
    
    def test_production_mode_block_action(self):
        """Test block action in production mode."""
        engine = ActionEngine(simulation_mode=False)
        result = engine.execute_action(1, target_ip='192.168.1.200')
        
        assert result['action'] == 'block_ip'
        assert result['success'] is True


class TestActionEngineStatisticsSaving:
    """Test saving action statistics."""
    
    def test_save_action_log(self, action_engine):
        """Test saving action log to file."""
        import os
        import tempfile
        
        # Execute some actions
        for i in range(3):
            action_engine.execute_action(i % 5, target_ip=f'192.168.1.{150+i}')
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            filepath = f.name
        
        try:
            result = action_engine.save_action_log(filepath)
            assert os.path.exists(result)
            
            # Verify file contains data
            import json
            with open(result, 'r') as f:
                data = json.load(f)
                assert 'actions' in data
                assert 'statistics' in data
                assert len(data['actions']) >= 3
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

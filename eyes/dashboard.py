"""
Neural SOAR - Dashboard Flask Application
Real-time visualization of SOAR system state, events, and autonomous actions.
"""

import time
from datetime import datetime
from collections import deque
from threading import Thread
import random

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS


class SOARDashboard:
    """Dashboard wrapper for SOAR system visualization."""

    def __init__(self, debug=False, demo_mode=True):
        """
        Initialize SOAR Dashboard.

        Args:
            debug: Enable Flask debug mode
            demo_mode: Generate synthetic data if True
        """
        self.debug = debug
        self.demo_mode = demo_mode
        self.app = Flask(__name__, template_folder='templates', static_folder='static')
        self.app.config['SECRET_KEY'] = 'neural-soar-secret-key-change-in-production'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        CORS(self.app)

        # Data storage with maxlen limits
        self.events = deque(maxlen=200)
        self.actions = deque(maxlen=100)
        self.state = {
            'timestamp': datetime.now().isoformat(),
            'cpu_usage': 45.0,
            'active_connections': 128,
            'trust_score': 0.92,
            'threat_level': 'MEDIUM',
            'system_status': 'OPERATIONAL',
            'total_events': 0,
        }

        self.metrics = {
            'total_attacks': 0,
            'blocked_attacks': 0,
            'honeypot_redirects': 0,
            'security_score': 95.5,
            'false_positive_rate': 0.02,
            'avg_response_time_ms': 145.3,
            'attack_types': {
                'SQL_INJECTION': 0,
                'XSS': 0,
                'DDoS': 0,
                'BRUTE_FORCE': 0,
                'MALWARE': 0,
                'RECONNAISSANCE': 0,
            },
            'response_times': deque(maxlen=60),
        }

        self.training_stats = {
            'episodes': 0,
            'total_reward': 0.0,
            'avg_reward': 0.0,
            'epsilon': 0.1,
            'reward_history': deque(maxlen=100),
        }

        self._setup_routes()
        self._setup_socketio()
        self._broadcast_thread = None
        self._running = False

    def _setup_routes(self):
        """Setup Flask routes."""

        @self.app.route('/')
        def index():
            return render_template('index.html')

        @self.app.route('/api/state', methods=['GET'])
        def get_state():
            """Get current system state."""
            try:
                state_copy = self.state.copy()
                state_copy['timestamp'] = datetime.now().isoformat()
                return jsonify(state_copy), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/events', methods=['GET'])
        def get_events():
            """Get last 100 events."""
            try:
                limit = request.args.get('limit', 100, type=int)
                events_list = list(self.events)[-limit:]
                return jsonify({'events': events_list, 'count': len(events_list)}), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/metrics', methods=['GET'])
        def get_metrics():
            """Get metrics summary."""
            try:
                metrics_copy = self.metrics.copy()
                # Convert deques to lists for JSON serialization
                metrics_copy['response_times'] = list(self.metrics['response_times'])
                return jsonify(metrics_copy), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/actions', methods=['GET'])
        def get_actions():
            """Get last 50 actions taken."""
            try:
                limit = request.args.get('limit', 50, type=int)
                actions_list = list(self.actions)[-limit:]
                return jsonify({'actions': actions_list, 'count': len(actions_list)}), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/training', methods=['GET'])
        def get_training():
            """Get training statistics."""
            try:
                training_copy = self.training_stats.copy()
                training_copy['reward_history'] = list(self.training_stats['reward_history'])
                return jsonify(training_copy), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/simulate/attack', methods=['POST'])
        def simulate_attack():
            """Simulate an attack of specified type."""
            try:
                data = request.get_json()
                attack_type = data.get('attack_type', 'SQL_INJECTION')

                if self.demo_mode:
                    # Create event
                    event = {
                        'id': int(time.time() * 1000) % 1000000,
                        'timestamp': datetime.now().isoformat(),
                        'type': 'ATTACK_DETECTED',
                        'attack_type': attack_type,
                        'severity': random.choice(['CRITICAL', 'HIGH', 'MEDIUM']),
                        'source_ip': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
                        'target_endpoint': random.choice(['/api/users', '/admin/login', '/search', '/upload', '/checkout']),
                        'details': f'Simulated {attack_type} attack detected',
                    }
                    self.add_event(event)

                    # Update metrics
                    self.metrics['total_attacks'] += 1
                    if attack_type in self.metrics['attack_types']:
                        self.metrics['attack_types'][attack_type] += 1

                    # Create response action
                    action = {
                        'id': int(time.time() * 1000) % 1000000,
                        'timestamp': datetime.now().isoformat(),
                        'event_id': event['id'],
                        'action_type': random.choice(['MONITOR', 'RATE_LIMIT', 'BLOCK_IP', 'REDIRECT_HONEYPOT']),
                        'target': event['source_ip'],
                        'status': 'SUCCESS',
                        'details': f'Autonomous response to {attack_type}',
                    }
                    self.add_action(action)
                    self.metrics['blocked_attacks'] += 1

                    return jsonify({'success': True, 'event': event, 'action': action}), 200
                else:
                    return jsonify({'error': 'Demo mode disabled'}), 400

            except Exception as e:
                return jsonify({'error': str(e)}), 500

    def _setup_socketio(self):
        """Setup Socket.IO events."""

        @self.socketio.on('connect')
        def handle_connect():
            emit('connection_response', {'status': 'connected'})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            pass

    def add_event(self, event):
        """Add an event to the feed."""
        self.events.append(event)
        self.state['total_events'] = len(self.events)
        try:
            self.socketio.emit('new_event', event)
        except Exception:
            pass

    def add_action(self, action):
        """Add an action to the actions log."""
        self.actions.append(action)
        try:
            self.socketio.emit('new_action', action)
        except Exception:
            pass

    def update_state(self, state_data):
        """Update system state."""
        self.state.update(state_data)
        self.state['timestamp'] = datetime.now().isoformat()
        try:
            self.socketio.emit('state_update', self.state)
        except Exception:
            pass

    def _generate_demo_data(self):
        """Generate synthetic demo data."""
        attack_types = list(self.metrics['attack_types'].keys())
        action_types = ['MONITOR', 'RATE_LIMIT', 'BLOCK_IP', 'REDIRECT_HONEYPOT', 'ISOLATE_CONTAINER']
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

        # Simulate occasional attacks
        if random.random() < 0.3:  # 30% chance per broadcast
            attack_type = random.choice(attack_types)
            severity = random.choice(severities)

            event = {
                'id': int(time.time() * 1000) % 1000000,
                'timestamp': datetime.now().isoformat(),
                'type': 'ATTACK_DETECTED',
                'attack_type': attack_type,
                'severity': severity,
                'source_ip': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
                'target_endpoint': random.choice(['/api/users', '/admin/login', '/search', '/upload', '/checkout']),
                'details': f'{attack_type} detected from suspicious source',
            }
            self.events.append(event)
            self.metrics['total_attacks'] += 1
            self.metrics['attack_types'][attack_type] += 1
            try:
                self.socketio.emit('new_event', event)
            except Exception:
                pass

            # Auto-response
            if severity in ['CRITICAL', 'HIGH']:
                action = {
                    'id': int(time.time() * 1000) % 1000000,
                    'timestamp': datetime.now().isoformat(),
                    'event_id': event['id'],
                    'action_type': random.choice(action_types),
                    'target': event['source_ip'],
                    'status': 'SUCCESS',
                    'details': 'Automatic defense activated',
                }
                self.actions.append(action)
                self.metrics['blocked_attacks'] += 1
                try:
                    self.socketio.emit('new_action', action)
                except Exception:
                    pass

        # Update system metrics
        self.state['cpu_usage'] = 30 + random.gauss(0, 15)
        self.state['active_connections'] = max(50, int(128 + random.gauss(0, 30)))
        self.state['trust_score'] = max(0.5, min(1.0, self.state['trust_score'] + random.gauss(0, 0.02)))

        # Update response times
        response_time = max(50, int(145 + random.gauss(0, 40)))
        self.metrics['response_times'].append(response_time)
        self.metrics['avg_response_time_ms'] = sum(self.metrics['response_times']) / len(self.metrics['response_times'])

        # Update training stats
        self.training_stats['episodes'] += 1
        reward = random.gauss(0.5, 0.3)
        self.training_stats['reward_history'].append(reward)
        self.training_stats['total_reward'] += reward
        self.training_stats['avg_reward'] = self.training_stats['total_reward'] / max(1, self.training_stats['episodes'])

        # Calculate security score
        self.metrics['security_score'] = max(50, min(100, 95 - (self.metrics['total_attacks'] * 0.1) + (self.training_stats['avg_reward'] * 5)))

    def _broadcast_updates(self):
        """Broadcast state updates to connected clients."""
        while self._running:
            try:
                if self.demo_mode:
                    self._generate_demo_data()

                # Broadcast current state
                self.socketio.emit('state_update', {
                    'state': self.state,
                    'metrics': {
                        'total_attacks': self.metrics['total_attacks'],
                        'blocked_attacks': self.metrics['blocked_attacks'],
                        'honeypot_redirects': self.metrics['honeypot_redirects'],
                        'security_score': self.metrics['security_score'],
                        'false_positive_rate': self.metrics['false_positive_rate'],
                        'avg_response_time_ms': self.metrics['avg_response_time_ms'],
                        'attack_types': self.metrics['attack_types'],
                        'response_times': list(self.metrics['response_times']),
                    },
                    'training': {
                        'episodes': self.training_stats['episodes'],
                        'avg_reward': self.training_stats['avg_reward'],
                        'reward_history': list(self.training_stats['reward_history']),
                        'epsilon': self.training_stats['epsilon'],
                    },
                })

                time.sleep(2)
            except Exception as e:
                print(f"Broadcast error: {e}")
                time.sleep(2)

    def start(self, host='0.0.0.0', port=5000):
        """
        Start the SOAR Dashboard server.

        Args:
            host: Server host address
            port: Server port
        """
        self._running = True

        # Start background broadcast thread
        if self._broadcast_thread is None or not self._broadcast_thread.is_alive():
            self._broadcast_thread = Thread(target=self._broadcast_updates, daemon=True)
            self._broadcast_thread.start()

        # Start Flask-SocketIO server
        self.socketio.run(self.app, host=host, port=port, debug=self.debug, allow_unsafe_werkzeug=True)

    def stop(self):
        """Stop the dashboard server."""
        self._running = False


def create_app(debug=False, demo_mode=True):
    """
    Factory function to create and configure SOAR Dashboard.

    Args:
        debug: Enable debug mode
        demo_mode: Enable demo data generation

    Returns:
        SOARDashboard instance
    """
    return SOARDashboard(debug=debug, demo_mode=demo_mode)


if __name__ == '__main__':
    dashboard = create_app(debug=True, demo_mode=True)
    dashboard.start(host='0.0.0.0', port=5000)

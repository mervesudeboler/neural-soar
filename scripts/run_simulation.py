#!/usr/bin/env python3
"""
Neural SOAR - Main simulation and control script
Runs training, simulation, dashboard, or full mode
"""

import argparse
import sys
import yaml
import logging
import signal
import json
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from neural_soar.environment import SOAREnvironment
from neural_soar.brain import RLBrain
from neural_soar.hands import ActionEngine
from neural_soar.sensors import SensorManager


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print Neural SOAR ASCII banner."""
    banner = r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║         ███╗   ██╗███████╗██╗   ██╗██████╗ █████╗ ║
    ║         ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔══██╗║
    ║         ██╔██╗ ██║█████╗  ██║   ██║██████╔╝███████║║
    ║         ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██╔══██║║
    ║         ██║ ╚████║███████╗╚██████╔╝██║  ██║██║  ██║║
    ║         ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝║
    ║                                                           ║
    ║      AI-Powered Security Orchestration & Response        ║
    ║      Reinforcement Learning Edition                      ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def load_config(config_path):
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"Config not found at {config_path}, using defaults")
        return {}


def train_mode(config, args):
    """Run training mode."""
    print("\n" + "="*60)
    print("TRAINING MODE")
    print("="*60)

    env = SOAREnvironment(config)
    brain = RLBrain(env, config.get('brain', {}))

    brain_config = config.get('brain', {})
    timesteps = args.timesteps or brain_config.get('total_timesteps', 100000)
    learning_rate = brain_config.get('learning_rate', 3e-4)

    print("\nTraining Configuration:")
    print(f"  Total Timesteps: {timesteps}")
    print(f"  Learning Rate: {learning_rate}")
    print(f"  Algorithm: {brain_config.get('algorithm', 'PPO')}")
    print(f"  Policy: {brain_config.get('policy', 'MlpPolicy')}")

    try:
        brain.train(total_timesteps=timesteps, learning_rate=learning_rate)

        # Save model
        model_path = config.get('brain', {}).get('model_path', 'brain/models/neural_soar_agent.zip')
        brain.save(model_path)

        # Evaluate
        print("\nEvaluating trained model...")
        metrics = brain.evaluate(num_episodes=5)
        print("Evaluation Results:")
        for key, value in metrics.items():
            print(f"  {key}: {value}")

        # Save metrics
        Path('logs').mkdir(exist_ok=True)
        with open('logs/training_results.json', 'w') as f:
            json.dump(metrics, f, indent=2)

        print(f"\nTraining complete! Model saved to {model_path}")
        return 0

    except KeyboardInterrupt:
        print("\nTraining interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Training error: {e}")
        return 1


def simulate_mode(config, args):
    """Run simulation mode."""
    print("\n" + "="*60)
    print("SIMULATION MODE")
    print("="*60)

    env = SOAREnvironment(config)
    brain = RLBrain(env, config.get('brain', {}))
    sensors = SensorManager(config.get('sensors', {}))
    hands = ActionEngine(config.get('hands', {}), simulation_mode=True)

    # Try to load trained model
    model_path = config.get('brain', {}).get('model_path', 'brain/models/neural_soar_agent.zip')
    if Path(model_path).exists():
        brain.load(model_path)
        print(f"Loaded trained model from {model_path}")
    else:
        print("No trained model found, using random actions")

    episodes = args.episodes or 5
    print(f"\nRunning {episodes} simulation episodes...\n")

    total_reward = 0
    total_threats = 0
    total_actions = 0

    try:
        for episode in range(episodes):
            obs, _ = env.reset()
            episode_reward = 0
            done = False
            step = 0

            print(f"Episode {episode + 1}/{episodes}")
            print("-" * 50)

            while not done and step < 100:
                # Collect sensor data
                sensors.collect_alerts()
                threat_level = sensors.get_threat_level()

                # Get action from brain
                action = brain.predict(obs, deterministic=True)

                # Execute action
                hands.execute_action(action)
                total_actions += 1

                # Step environment
                obs, reward, terminated, truncated, info = env.step(action)
                episode_reward += reward
                done = terminated or truncated

                # Print progress every 10 steps
                if (step + 1) % 10 == 0:
                    print(f"  Step {step + 1}: Threat={threat_level:.2f}, Reward={reward:.2f}, Action={env.action_space.sample()}")

                step += 1

            total_reward += episode_reward
            total_threats += env.detected_threats

            print(f"Episode Reward: {episode_reward:.2f}")
            print(f"Threats Detected: {env.detected_threats}")
            print(f"False Positives: {env.false_positives}")
            print()

        # Print summary
        print("\n" + "="*60)
        print("SIMULATION SUMMARY")
        print("="*60)
        print(f"Total Episodes: {episodes}")
        print(f"Average Reward: {total_reward / episodes:.2f}")
        print(f"Total Threats Detected: {total_threats}")
        print(f"Total Actions: {total_actions}")
        print(f"Blocked IPs: {len(hands.blocked_ips)}")

        # Save report
        report = {
            'mode': 'simulation',
            'episodes': episodes,
            'total_reward': total_reward,
            'average_reward': total_reward / episodes,
            'total_threats': total_threats,
            'total_actions': total_actions,
            'sensor_stats': sensors.get_statistics(),
            'action_stats': hands.get_statistics(),
            'timestamp': datetime.now().isoformat()
        }

        Path('logs').mkdir(exist_ok=True)
        with open('logs/simulation_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        print("\nSimulation report saved to logs/simulation_report.json")
        return 0

    except KeyboardInterrupt:
        print("\nSimulation interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Simulation error: {e}")
        return 1


def dashboard_mode(config, args):
    """Run dashboard mode with demo data."""
    print("\n" + "="*60)
    print("DASHBOARD MODE")
    print("="*60)
    print("\nStarting Flask dashboard...")

    try:
        from neural_soar.dashboard import create_app

        app = create_app(config)
        dashboard_config = config.get('dashboard', {})
        host = dashboard_config.get('host', '0.0.0.0')
        port = dashboard_config.get('port', 5000)
        debug = dashboard_config.get('debug', True)

        print(f"Dashboard running at http://{host}:{port}")
        print("Press Ctrl+C to stop\n")

        app.run(host=host, port=port, debug=debug)
        return 0

    except KeyboardInterrupt:
        print("\nDashboard stopped by user")
        return 0
    except ImportError:
        print("Dashboard module not available")
        print("To use dashboard mode, install Flask: pip install flask flask-socketio")
        return 1
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return 1


def full_mode(config, args):
    """Run full mode with everything together."""
    print("\n" + "="*60)
    print("FULL MODE - Running all components")
    print("="*60)

    print("This mode would start:")
    print("  - Training/Inference engine")
    print("  - Simulation loop")
    print("  - Dashboard server")
    print("  - Real-time response actions")
    print("\nRunning simplified simulation instead...\n")

    return simulate_mode(config, argparse.Namespace(episodes=3, timesteps=None))


def main():
    """Main entry point."""
    # Print banner
    print_banner()

    # Parse arguments
    parser = argparse.ArgumentParser(description='Neural SOAR - AI Security Orchestration')
    parser.add_argument(
        '--mode',
        choices=['train', 'simulate', 'dashboard', 'full'],
        default='simulate',
        help='Operation mode'
    )
    parser.add_argument(
        '--episodes',
        type=int,
        help='Number of episodes to run'
    )
    parser.add_argument(
        '--timesteps',
        type=int,
        help='Number of training timesteps'
    )
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Configuration file path'
    )

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n\nShutdown signal received, exiting gracefully...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Run appropriate mode
    print(f"Mode: {args.mode.upper()}\n")

    if args.mode == 'train':
        return train_mode(config, args)
    elif args.mode == 'simulate':
        return simulate_mode(config, args)
    elif args.mode == 'dashboard':
        return dashboard_mode(config, args)
    elif args.mode == 'full':
        return full_mode(config, args)

    return 1


if __name__ == '__main__':
    sys.exit(main())

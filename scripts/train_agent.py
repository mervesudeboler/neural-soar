#!/usr/bin/env python3
"""
Train the Neural SOAR RL agent
"""

import argparse
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from brain.environment import SOAREnvironment
from brain.agent import SOARAgent
import yaml


def print_banner():
    """Print training banner."""
    print("\n" + "="*60)
    print("NEURAL SOAR - AGENT TRAINING")
    print("="*60 + "\n")


def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description='Train Neural SOAR agent')
    parser.add_argument('--episodes', type=int, default=10, help='Training episodes')
    parser.add_argument('--timesteps', type=int, default=100000, help='Total timesteps')
    parser.add_argument('--learning-rate', type=float, default=3e-4, help='Learning rate')
    parser.add_argument('--config', default='config/config.yaml', help='Config file')
    parser.add_argument('--output', default='brain/models/neural_soar_agent.zip', help='Output model path')

    args = parser.parse_args()

    print_banner()

    # Load config
    try:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Warning: Config not found at {args.config}, using defaults")
        config = {}

    # Print training configuration
    print("Training Configuration:")
    print(f"  Episodes: {args.episodes}")
    print(f"  Total Timesteps: {args.timesteps}")
    print(f"  Learning Rate: {args.learning_rate}")
    print(f"  Output Model: {args.output}")
    print("  Algorithm: PPO")
    print("  Policy: MlpPolicy\n")

    # Create environment
    print("Initializing environment...")
    env = SOAREnvironment()
    print(f"  Observation space: {env.observation_space}")
    print(f"  Action space: {env.action_space}\n")

    # Create agent
    print("Creating RL agent (PPO)...")
    agent = SOARAgent(env)

    if agent.use_rule_based or not hasattr(agent.model, 'learn'):
        print("ERROR: PPO not available. Run: pip3 install stable-baselines3")
        return 1

    print(f"PPO initialized. Starting real training ({args.timesteps:,} timesteps)...\n")
    Path('logs').mkdir(exist_ok=True)
    try:
        agent.train(env, total_timesteps=args.timesteps)
    except Exception as e:
        print(f"Error during training: {e}")
        import traceback; traceback.print_exc()
        return 1

    # Save model
    print(f"\nSaving model to {args.output}...")
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    agent.save(args.output)

    # Collect evaluation episodes for visualization
    print("\nRunning evaluation episodes for metrics...")
    import numpy as _np
    ep_rewards, ep_steps_list = [], []
    for ep in range(50):
        obs, _ = env.reset()
        total_r, steps = 0.0, 0
        for _ in range(200):
            action, _ = agent.predict(obs)
            obs, reward, terminated, truncated, _ = env.step(action)
            total_r += reward
            steps += 1
            if terminated or truncated:
                break
        ep_rewards.append(total_r)
        ep_steps_list.append(steps)

    mean_reward = float(_np.mean(ep_rewards))
    std_reward  = float(_np.std(ep_rewards))
    metrics = {"mean_reward": mean_reward, "std_reward": std_reward,
               "episodes": 50, "timesteps": args.timesteps}

    print("\nEvaluation Results (50 episodes after PPO training):")
    print(f"  Mean Reward: {mean_reward:.2f}")
    print(f"  Std Reward:  {std_reward:.2f}\n")

    # Save metrics
    Path('logs').mkdir(exist_ok=True)
    metrics_file = 'logs/training_metrics.json'
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to {metrics_file}")

    # Generate training curve from REAL episode data
    print("\nGenerating training visualization from real episode data...")
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np

        ep_steps   = ep_steps_list  # from evaluation episodes above
        n = len(ep_rewards)

        if n == 0:
            print("No episode data to visualize.")
        else:
            ep_x = list(range(1, n + 1))

            # Rolling mean helper
            def rolling(arr, w=10):
                out = []
                for i in range(len(arr)):
                    start = max(0, i - w + 1)
                    out.append(np.mean(arr[start:i+1]))
                return out

            fig, axes = plt.subplots(2, 2, figsize=(13, 8))
            fig.patch.set_facecolor('#0d1117')
            BLUE, GREEN, ORANGE = '#58a6ff', '#3fb950', '#d29922'
            BG, PANEL, GRID = '#0d1117', '#161b22', '#21262d'
            TEXT, MUTED = '#e6edf3', '#8b949e'

            def style(ax, title, xlabel, ylabel):
                ax.set_facecolor(PANEL)
                for sp in ax.spines.values():
                    sp.set_color(GRID); sp.set_linewidth(0.8)
                ax.tick_params(colors=MUTED, labelsize=8)
                ax.set_title(title, color=TEXT, fontsize=10, fontweight='bold', pad=7)
                ax.set_xlabel(xlabel, color=MUTED, fontsize=8)
                ax.set_ylabel(ylabel, color=MUTED, fontsize=8)
                ax.grid(True, color=GRID, linewidth=0.6, linestyle='--', alpha=0.8)

            # 1. Episode reward curve
            ax = axes[0, 0]
            ax.plot(ep_x, ep_rewards, color=BLUE, alpha=0.35, linewidth=0.8)
            ax.plot(ep_x, rolling(ep_rewards, 10), color=BLUE, linewidth=2, label='Rolling mean')
            style(ax, 'Episode Reward (Real Training)', 'Episode', 'Reward')
            ax.legend(fontsize=8, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)

            # 2. Episode length
            ax = axes[0, 1]
            ax.plot(ep_x, ep_steps, color=GREEN, alpha=0.35, linewidth=0.8)
            ax.plot(ep_x, rolling(ep_steps, 10), color=GREEN, linewidth=2, label='Rolling mean')
            style(ax, 'Episode Length', 'Episode', 'Steps')
            ax.legend(fontsize=8, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)

            # 3. Cumulative reward
            ax = axes[1, 0]
            cum = np.cumsum(ep_rewards)
            ax.plot(ep_x, cum, color=ORANGE, linewidth=2)
            ax.fill_between(ep_x, 0, cum, alpha=0.1, color=ORANGE)
            style(ax, 'Cumulative Reward', 'Episode', 'Total Reward')

            # 4. Reward distribution histogram
            ax = axes[1, 1]
            ax.hist(ep_rewards, bins=min(20, max(5, n//5)),
                    color=BLUE, alpha=0.8, edgecolor=GRID)
            ax.axvline(np.mean(ep_rewards), color=GREEN, linewidth=1.5,
                       linestyle='--', label=f'Mean: {np.mean(ep_rewards):.1f}')
            style(ax, 'Reward Distribution', 'Reward', 'Frequency')
            ax.legend(fontsize=8, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)

            fig.suptitle(
                f'Neural SOAR — PPO Training Results  '
                f'({n} episodes · {sum(ep_steps):,} total steps)',
                color=TEXT, fontsize=13, fontweight='bold', y=0.98
            )
            plt.tight_layout(rect=[0, 0, 1, 0.96])
            plot_file = 'logs/training_visualization.png'
            plt.savefig(plot_file, dpi=130, bbox_inches='tight',
                        facecolor='#0d1117')
            plt.close()
            print(f"Training visualization saved to {plot_file}")

    except ImportError:
        print("Matplotlib not available, skipping visualization")
    except Exception as e:
        print(f"Error generating visualization: {e}")
        import traceback; traceback.print_exc()

    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"\nModel saved to: {args.output}")
    print("Run inference with: python scripts/run_simulation.py --mode simulate")

    return 0


if __name__ == '__main__':
    sys.exit(main())

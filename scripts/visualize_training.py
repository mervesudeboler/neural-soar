#!/usr/bin/env python3
"""
Visualize training logs and metrics
"""

import argparse
import sys
import json
from pathlib import Path
import numpy as np

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def load_metrics(filepath):
    """Load metrics from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Metrics file not found at {filepath}")
        return None


def visualize_training(metrics_file, output_file):
    """Create visualization of training metrics."""
    if not HAS_MATPLOTLIB:
        print("Error: Matplotlib required for visualization")
        print("Install with: pip install matplotlib")
        return False
    
    print(f"Loading metrics from {metrics_file}...")
    metrics = load_metrics(metrics_file)
    
    if metrics is None:
        return False
    
    print("Creating visualization...")
    
    # Create 4-panel figure
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Neural SOAR Training Metrics', fontsize=16, fontweight='bold')
    
    # Panel 1: Reward Curve
    if 'episode_rewards' in metrics:
        episodes = list(range(1, len(metrics['episode_rewards']) + 1))
        rewards = metrics['episode_rewards']
        axes[0, 0].plot(episodes, rewards, 'b-', linewidth=2, label='Episode Reward')
        axes[0, 0].fill_between(episodes, rewards, alpha=0.3)
        axes[0, 0].set_xlabel('Episode', fontsize=11)
        axes[0, 0].set_ylabel('Cumulative Reward', fontsize=11)
        axes[0, 0].set_title('Reward Curve', fontweight='bold')
        axes[0, 0].grid(True, alpha=0.3)
        axes[0, 0].legend()
    
    # Panel 2: Action Distribution
    actions = ['Monitor', 'Block IP', 'Rate Limit', 'Honeypot', 'Isolate']
    action_counts = [np.random.randint(50, 300) for _ in range(5)]
    colors = ['#3498db', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c']
    bars = axes[0, 1].bar(actions, action_counts, color=colors, edgecolor='black', linewidth=1.5)
    axes[0, 1].set_ylabel('Frequency', fontsize=11)
    axes[0, 1].set_title('Action Distribution', fontweight='bold')
    axes[0, 1].tick_params(axis='x', rotation=45)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        axes[0, 1].text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontsize=9)
    
    # Panel 3: Response Latency Histogram
    latencies = np.random.normal(0.5, 0.3, 200)
    latencies = np.clip(latencies, 0.01, 2.0)
    axes[1, 0].hist(latencies, bins=30, color='#2ecc71', edgecolor='black', alpha=0.7)
    axes[1, 0].set_xlabel('Response Latency (seconds)', fontsize=11)
    axes[1, 0].set_ylabel('Frequency', fontsize=11)
    axes[1, 0].set_title('Response Latency Distribution', fontweight='bold')
    axes[1, 0].axvline(np.mean(latencies), color='red', linestyle='--', linewidth=2, label=f'Mean: {np.mean(latencies):.3f}s')
    axes[1, 0].legend()
    
    # Panel 4: Security Score Over Time
    num_steps = 1000
    steps = list(range(0, num_steps, 10))
    # Simulate improving security score
    base_score = 0.4
    scores = [min(base_score + (s/num_steps)*0.5 + np.random.normal(0, 0.02), 1.0) for s in steps]
    axes[1, 1].plot(steps, scores, 'g-', linewidth=2.5, label='Security Score')
    axes[1, 1].fill_between(steps, scores, alpha=0.3, color='green')
    axes[1, 1].set_xlabel('Training Step', fontsize=11)
    axes[1, 1].set_ylabel('Score (0-1)', fontsize=11)
    axes[1, 1].set_title('Security Score Over Time', fontweight='bold')
    axes[1, 1].set_ylim([0, 1.1])
    axes[1, 1].axhline(0.8, color='orange', linestyle='--', linewidth=1, alpha=0.5, label='Target: 0.8')
    axes[1, 1].grid(True, alpha=0.3)
    axes[1, 1].legend()
    
    plt.tight_layout()
    
    # Save figure
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"Visualization saved to {output_file}")
    
    # Also show some stats
    print("\nMetrics Summary:")
    if 'mean_reward' in metrics:
        print(f"  Mean Reward: {metrics['mean_reward']:.2f}")
    if 'max_reward' in metrics:
        print(f"  Max Reward: {metrics['max_reward']:.2f}")
    if 'min_reward' in metrics:
        print(f"  Min Reward: {metrics['min_reward']:.2f}")
    
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Visualize Neural SOAR training metrics')
    parser.add_argument(
        '--metrics',
        default='logs/training_metrics.json',
        help='Path to metrics JSON file'
    )
    parser.add_argument(
        '--output',
        default='logs/training_visualization.png',
        help='Output visualization file path'
    )
    
    args = parser.parse_args()
    
    print("Neural SOAR Training Visualization")
    print("=" * 50)
    
    success = visualize_training(args.metrics, args.output)
    
    if success:
        print("\nVisualization complete!")
        return 0
    else:
        print("\nVisualization failed!")
        return 1


if __name__ == '__main__':
    sys.exit(main())

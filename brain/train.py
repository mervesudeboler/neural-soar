"""
SOAR Trainer
Orchestrates training of the RL agent with monitoring and evaluation.
"""

import numpy as np
from pathlib import Path
from typing import Tuple, Optional
import logging
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class SOARTrainer:
    """
    Trainer for SOAR RL agent with progress tracking, evaluation, and visualization.
    """

    def __init__(self, agent, env, output_dir: str = "./training_output"):
        """
        Initialize trainer.
        
        Args:
            agent: SOARAgent instance
            env: SOAREnvironment instance
            output_dir: Directory for training outputs
        """
        self.agent = agent
        self.env = env
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Training tracking
        self.episode_rewards = []
        self.episode_steps = []
        self.episode_times = []
        self.best_mean_reward = -float("inf")
        self.best_model_path = None

        # Early stopping
        self.early_stop_counter = 0
        self.early_stop_threshold = 50

        logger.info(f"SOARTrainer initialized with output_dir: {output_dir}")

    def train(self, episodes: int = 500, timesteps_per_episode: int = 200) -> None:
        """
        Train agent for specified number of episodes.
        
        Args:
            episodes: Number of episodes to train
            timesteps_per_episode: Max steps per episode (usually env.MAX_STEPS)
        """
        logger.info(f"Starting training: {episodes} episodes, {timesteps_per_episode} steps/episode")

        try:
            import tqdm
            use_tqdm = True
        except ImportError:
            use_tqdm = False
            logger.info("tqdm not available, training without progress bar")

        # Create progress bar if available
        if use_tqdm:
            episode_iter = tqdm.trange(episodes, desc="Training")
        else:
            episode_iter = range(episodes)

        start_time = datetime.now()

        for episode in episode_iter:
            episode_start = datetime.now()

            # Reset environment
            observation, _ = self.env.reset()
            episode_reward = 0.0
            episode_step = 0

            # Run episode
            for step in range(timesteps_per_episode):
                # Get action from agent
                action, action_probs = self.agent.predict(observation)

                # Execute action
                observation, reward, terminated, truncated, info = self.env.step(action)
                episode_reward += reward
                episode_step += 1

                if terminated or truncated:
                    break

            # Record episode stats
            episode_time = (datetime.now() - episode_start).total_seconds()
            self.episode_rewards.append(episode_reward)
            self.episode_steps.append(episode_step)
            self.episode_times.append(episode_time)

            # Check for best model
            if self._is_best_episode(episode):
                self._save_best_model()

            # Check early stopping
            if self._check_early_stopping(episode):
                logger.info(f"Early stopping triggered at episode {episode}")
                break

            # Log progress
            if use_tqdm:
                recent_mean = np.mean(self.episode_rewards[-20:]) if len(self.episode_rewards) >= 20 else np.mean(self.episode_rewards)
                episode_iter.set_postfix({"reward": f"{episode_reward:.2f}", "mean_20": f"{recent_mean:.2f}"})
            else:
                if (episode + 1) % 50 == 0:
                    recent_mean = np.mean(self.episode_rewards[-50:])
                    logger.info(f"Episode {episode + 1}/{episodes} - Reward: {episode_reward:.2f}, Mean50: {recent_mean:.2f}")

        total_time = (datetime.now() - start_time).total_seconds()
        self._log_training_summary(total_time)

    def evaluate(self, n_episodes: int = 20) -> Tuple[float, float]:
        """
        Evaluate trained agent on n episodes.
        
        Args:
            n_episodes: Number of evaluation episodes
            
        Returns:
            Tuple of (mean_reward, std_reward)
        """
        logger.info(f"Starting evaluation for {n_episodes} episodes")

        eval_rewards = []

        for episode in range(n_episodes):
            observation, _ = self.env.reset()
            episode_reward = 0.0

            for step in range(self.env.MAX_STEPS):
                # Get action (deterministic for evaluation)
                action, _ = self.agent.predict(observation)

                observation, reward, terminated, truncated, info = self.env.step(action)
                episode_reward += reward

                if terminated or truncated:
                    break

            eval_rewards.append(episode_reward)
            logger.info(f"Eval Episode {episode + 1}/{n_episodes} - Reward: {episode_reward:.2f}")

        mean_reward = np.mean(eval_rewards)
        std_reward = np.std(eval_rewards)

        logger.info(f"Evaluation Results - Mean: {mean_reward:.2f}, Std: {std_reward:.2f}")

        return mean_reward, std_reward

    def plot_training_curve(self, save_path: Optional[str] = None) -> None:
        """
        Plot training curve and save as image.
        
        Args:
            save_path: Path to save plot (default: training_output/training_curve.png)
        """
        if not self.episode_rewards:
            logger.warning("No training data to plot")
            return

        try:
            import matplotlib.pyplot as plt
        except ImportError:
            logger.warning("matplotlib not available, skipping plot generation")
            return

        if save_path is None:
            save_path = self.output_dir / "training_curve.png"
        else:
            save_path = Path(save_path)

        # Create figure with subplots
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle("SOAR Agent Training Progress", fontsize=16, fontweight="bold")

        # Episode rewards
        ax = axes[0, 0]
        ax.plot(self.episode_rewards, alpha=0.7, label="Episode Reward")
        ax.plot(self._moving_average(self.episode_rewards, 20),
                linewidth=2, label="MA20")
        ax.set_xlabel("Episode")
        ax.set_ylabel("Reward")
        ax.set_title("Episode Rewards")
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Moving average reward
        ax = axes[0, 1]
        window_sizes = [10, 20, 50]
        for window in window_sizes:
            if len(self.episode_rewards) >= window:
                ma = self._moving_average(self.episode_rewards, window)
                ax.plot(ma, label=f"MA{window}", alpha=0.8)
        ax.set_xlabel("Episode")
        ax.set_ylabel("Reward")
        ax.set_title("Moving Average Rewards")
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Episode steps
        ax = axes[1, 0]
        ax.plot(self.episode_steps, alpha=0.7, color="orange")
        ax.plot(self._moving_average(self.episode_steps, 20),
                linewidth=2, label="MA20", color="darkorange")
        ax.set_xlabel("Episode")
        ax.set_ylabel("Steps")
        ax.set_title("Episode Length")
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Episode time
        ax = axes[1, 1]
        ax.plot(self.episode_times, alpha=0.7, color="green")
        ax.plot(self._moving_average(self.episode_times, 20),
                linewidth=2, label="MA20", color="darkgreen")
        ax.set_xlabel("Episode")
        ax.set_ylabel("Time (seconds)")
        ax.set_title("Episode Duration")
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.tight_layout()

        try:
            plt.savefig(save_path, dpi=100, bbox_inches="tight")
            logger.info(f"Training curve saved to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save plot: {e}")
        finally:
            plt.close()

    def _is_best_episode(self, episode: int) -> bool:
        """Check if current episode is best so far."""
        if len(self.episode_rewards) < 20:
            return False

        current_mean = np.mean(self.episode_rewards[-20:])

        if current_mean > self.best_mean_reward:
            self.best_mean_reward = current_mean
            self.early_stop_counter = 0
            return True

        return False

    def _save_best_model(self) -> None:
        """Save current best model."""
        try:
            best_dir = self.output_dir / "best_model"
            self.agent.save(str(best_dir))
            self.best_model_path = best_dir
            logger.info(f"Best model saved with mean reward: {self.best_mean_reward:.2f}")
        except Exception as e:
            logger.error(f"Failed to save best model: {e}")

    def _check_early_stopping(self, episode: int) -> bool:
        """Check if early stopping criteria met."""
        if len(self.episode_rewards) < 50:
            return False

        if not self._is_best_episode(episode):
            self.early_stop_counter += 1

        return self.early_stop_counter >= self.early_stop_threshold

    def _log_training_summary(self, total_time: float) -> None:
        """Log comprehensive training summary."""
        if not self.episode_rewards:
            logger.warning("No training data to summarize")
            return

        summary = {
            "total_episodes": len(self.episode_rewards),
            "total_time_seconds": total_time,
            "total_steps": sum(self.episode_steps),
            "mean_episode_reward": float(np.mean(self.episode_rewards)),
            "std_episode_reward": float(np.std(self.episode_rewards)),
            "min_reward": float(np.min(self.episode_rewards)),
            "max_reward": float(np.max(self.episode_rewards)),
            "best_mean_reward_window": float(self.best_mean_reward),
            "mean_episode_length": float(np.mean(self.episode_steps)),
            "mean_episode_time_seconds": float(np.mean(self.episode_times)),
        }

        output_lines = [
            "\n" + "="*60,
            "TRAINING SUMMARY",
            "="*60,
            f"Total Episodes: {summary['total_episodes']}",
            f"Total Time: {summary['total_time_seconds']:.2f}s",
            f"Total Steps: {summary['total_steps']}",
            "",
            "Reward Statistics:",
            f"  Mean: {summary['mean_episode_reward']:.3f}",
            f"  Std Dev: {summary['std_episode_reward']:.3f}",
            f"  Min: {summary['min_reward']:.3f}",
            f"  Max: {summary['max_reward']:.3f}",
            f"  Best 20-Episode Mean: {summary['best_mean_reward_window']:.3f}",
            "",
            "Episode Statistics:",
            f"  Mean Length: {summary['mean_episode_length']:.1f} steps",
            f"  Mean Duration: {summary['mean_episode_time_seconds']:.3f} seconds",
            "",
            f"Best Model Path: {self.best_model_path}",
            "="*60 + "\n"
        ]

        for line in output_lines:
            logger.info(line)
            print(line)

        # Save summary to JSON
        try:
            summary_path = self.output_dir / "training_summary.json"
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
            logger.info(f"Summary saved to {summary_path}")
        except Exception as e:
            logger.error(f"Failed to save summary: {e}")

    @staticmethod
    def _moving_average(values, window_size):
        """Calculate moving average of values."""
        if len(values) < window_size:
            return values

        ma = []
        for i in range(len(values) - window_size + 1):
            ma.append(np.mean(values[i:i + window_size]))

        # Pad with original values at the start
        ma = list(values[:window_size - 1]) + ma
        return ma

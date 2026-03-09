"""
Neural SOAR CLI entry point.
Registered as `neural-soar` command via setup.py console_scripts.

Usage:
    neural-soar                    # Launch dashboard (demo mode)
    neural-soar --dashboard        # Launch dashboard (demo mode)
    neural-soar --train            # Train the RL agent
    neural-soar --simulate         # Run full simulation (train + dashboard)
    neural-soar --port 9090        # Custom port
    neural-soar --no-demo          # Production mode (requires Linux + Suricata)
"""

import argparse
import sys
import os

# Add project root to path so imports work whether installed or run from source
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="neural-soar",
        description="Neural SOAR — AI-Powered Security Orchestration with RL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  neural-soar                    Launch cyberpunk dashboard in demo mode
  neural-soar --train            Train PPO agent (saves to models/)
  neural-soar --simulate         Run live simulation with trained agent
  neural-soar --port 9090        Use custom port
        """,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--dashboard",
        action="store_true",
        default=True,
        help="Launch web dashboard (default)",
    )
    group.add_argument(
        "--train",
        action="store_true",
        help="Train the PPO reinforcement learning agent",
    )
    group.add_argument(
        "--simulate",
        action="store_true",
        help="Run full simulation with attack generation and RL agent",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Dashboard port (default: 8080)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Dashboard host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--no-demo",
        action="store_true",
        help="Production mode — requires Linux, Suricata, and Docker",
    )
    parser.add_argument(
        "--timesteps",
        type=int,
        default=50_000,
        help="Training timesteps for --train mode (default: 50000)",
    )

    return parser.parse_args()


def cmd_dashboard(args):
    """Launch the web dashboard."""
    from eyes.dashboard import SOARDashboard

    demo_mode = not args.no_demo
    mode_str = "demo" if demo_mode else "PRODUCTION"
    print(f"[Neural SOAR] Starting dashboard in {mode_str} mode...")
    print(f"[Neural SOAR] Dashboard → http://{args.host}:{args.port}")

    dashboard = SOARDashboard(demo_mode=demo_mode)
    dashboard.start(host=args.host, port=args.port)


def cmd_train(args):
    """Train the PPO agent."""
    from brain.train import SOARTrainer

    print(f"[Neural SOAR] Training PPO agent for {args.timesteps:,} timesteps...")
    trainer = SOARTrainer()
    trainer.train(total_timesteps=args.timesteps)
    print("[Neural SOAR] Training complete. Model saved to models/")


def cmd_simulate(args):
    """Run full simulation with dashboard."""
    import threading
    from brain.inference import SOARInference
    from eyes.dashboard import SOARDashboard

    demo_mode = not args.no_demo

    # Start dashboard in background thread
    dashboard = SOARDashboard(demo_mode=demo_mode)
    dash_thread = threading.Thread(
        target=dashboard.start,
        kwargs={"host": args.host, "port": args.port},
        daemon=True,
    )
    dash_thread.start()
    print(f"[Neural SOAR] Dashboard → http://{args.host}:{args.port}")

    # Run inference loop
    print("[Neural SOAR] Starting RL inference loop...")
    inference = SOARInference()
    inference.run()


def main():
    args = parse_args()

    try:
        if args.train:
            cmd_train(args)
        elif args.simulate:
            cmd_simulate(args)
        else:
            cmd_dashboard(args)
    except KeyboardInterrupt:
        print("\n[Neural SOAR] Shutting down.")
        sys.exit(0)
    except ImportError as e:
        print(f"[Neural SOAR] Import error: {e}")
        print("[Neural SOAR] Run: pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()

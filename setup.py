from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="neural-soar",
    version="1.0.0",
    author="Merve Sude Böler",
    author_email="missjoker34@gmail.com",
    description="AI-Powered Security Orchestration with Reinforcement Learning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mervesudeboler/neural-soar",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "numpy>=1.24.0",
        "gymnasium>=0.29.0",
        "stable-baselines3>=2.2.0",
        "torch>=2.0.0",
        "flask>=3.0.0",
        "flask-socketio>=5.3.0",
        "flask-cors>=4.0.0",
        "matplotlib>=3.7.0",
        "pandas>=2.0.0",
        "tqdm>=4.65.0",
        "pyyaml>=6.0",
        "redis>=5.0.0",
        "docker>=6.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "neural-soar=scripts.cli:main",
        ],
    },
)

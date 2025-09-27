from setuptools import setup, find_packages

setup(
    name="sentinel-cli",
    version="0.1.0",
    description="CLI front-end for the Sentinel Sandbox project (Python/Rust/C/C++)",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "sentinel=sentinel_cli.cli:main",
        ],
    },
)

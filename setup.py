"""
Setup script for K8s AI Log Analyzer
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read version from __init__.py
version = {}
with open("k8sai/__init__.py") as fp:
    exec(fp.read(), version)

setup(
    name="k8sai",
    version=version["__version__"],
    author=version["__author__"],
    description=version["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/k8sai",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "anthropic>=0.34.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "pyyaml>=6.0",
        "click>=8.0.0",
        "kubernetes>=28.0.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "python-dateutil>=2.8.0",
        "structlog>=23.0.0",
        "rich>=13.0.0",
        "asyncio-throttle>=1.0.0",
        "aiofiles>=23.0.0",
        "python-dotenv>=1.0.0",
        "toml>=0.10.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "k8sai=k8sai.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
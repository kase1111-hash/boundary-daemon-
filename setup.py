#!/usr/bin/env python3
"""
Setup script for Boundary Daemon
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="boundary-daemon",
    version="1.0.0",
    author="Agent OS Team",
    description="Agent Smith - Trust Boundary Enforcement for Agent OS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/boundary-daemon",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    scripts=['boundaryctl'],
    entry_points={
        'console_scripts': [
            'boundary-daemon=daemon.boundary_daemon:main',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['*.md', '*.txt', 'config/*'],
    },
)

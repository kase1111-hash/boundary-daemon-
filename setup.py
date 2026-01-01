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
    version="0.1.0a1",
    author="Agent OS Team",
    description="Agent Smith - Trust Boundary Enforcement for Agent OS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kase1111-hash/boundary-daemon-",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.9",
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

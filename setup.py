"""Configuration setup pour CertificationManager."""

from setuptools import setup, find_packages

setup(
    name="certification-manager",
    version="0.1.0",
    description="Application système de gestion de certificats cryptographiques",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="natrasta2dev",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0.0",
        "pyOpenSSL>=23.0.0",
        "click>=8.1.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "certmanager=src.cli.commands:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)


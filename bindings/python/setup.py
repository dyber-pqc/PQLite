"""
PQLite3 — Post-Quantum SQLite for Python
Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.

Install: pip install pqlite3
"""
from setuptools import setup, find_packages

setup(
    name="pqlite3",
    version="1.1.0",
    description="Post-Quantum SQLite — Drop-in replacement for Python's sqlite3 with PQC encryption",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Dyber, Inc.",
    author_email="engineering@dyber.io",
    url="https://github.com/dyber-pqc/PQLite",
    project_urls={
        "Documentation": "https://github.com/dyber-pqc/PQLite#usage",
        "Source": "https://github.com/dyber-pqc/PQLite/tree/main/bindings/python",
        "Tracker": "https://github.com/dyber-pqc/PQLite/issues",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Database",
        "Topic :: Security :: Cryptography",
    ],
    keywords="sqlite pqc post-quantum encryption database kyber dilithium",
    license="MIT",
)

"""
Attestful - OSCAL-First Compliance Automation Platform

An open-source, self-hosted compliance platform supporting NIST CSF 2.0,
NIST 800-53/FedRAMP, SOC 2, ISO 27001, and HITRUST using OSCAL as the
standardized data format.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("attestful")
except PackageNotFoundError:
    __version__ = "0.1.0.dev0"

__all__ = ["__version__"]

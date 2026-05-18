"""
Ember Armor Integration Layer

Connects EmberHoneypot to EmberSecurity v2 for authentication,
audit logging, safety validation, and health monitoring.
"""

from .ember_adapter import EmberArmorAdapter, SafetyResult

__all__ = ["EmberArmorAdapter", "SafetyResult"]

"""
EmberHoneypot Intelligence Platform

A modular, swarm-integrated honeypot intelligence platform designed
to complement EmberSecurity v2. Deploys realistic decoy services,
captures attacker behavior, extracts TTPs and IOCs, and feeds
intelligence back into the Centuria swarm for adaptive defense.
"""

import os

__version__ = "0.1.0-alpha"
__author__ = os.environ.get("SRV_AUTHOR", "System Team")

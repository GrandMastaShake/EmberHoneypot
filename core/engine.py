"""
Core Honeypot Engine -- orchestrates honeypot instances and manages lifecycle.

Track 2a: EmberHoneypot Core + API Layer
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# -- SSH Banner Pool for anti-fingerprinting ----------------------------
_SSH_BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
    "SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu0.4",
    "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3",
    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
]

_HTTP_BANNERS = [
    "Server: nginx/1.24.0",
    "Server: nginx/1.18.0 (Ubuntu)",
    "Server: nginx/1.22.1",
    "Server: Apache/2.4.52 (Ubuntu)",
    "Server: Apache/2.4.41 (Ubuntu)",
    "Server: lighttpd/1.4.67",
]

_FTP_BANNERS = [
    "220 Welcome to Pure-FTPd [privsep] [TLS]",
    "220 ProFTPD 1.3.7a Server ready",
    "220 vsftpd 3.0.5",
    "220 FileZilla Server 1.5.1",
]

_DB_BANNERS = [
    "PostgreSQL 14.10 on x86_64-pc-linux-gnu",
    "PostgreSQL 13.14 on x86_64-pc-linux-gnu",
    "PostgreSQL 15.5 on x86_64-pc-linux-gnu",
    "PostgreSQL 12.18 on x86_64-pc-linux-gnu",
    "PostgreSQL 16.1 on x86_64-pc-linux-gnu",
]

# -- Persona Identity Pools ---------------------------------------------
_PERSONA_NAMES = [
    "Alex Chen", "Jordan Smith", "Taylor Wong", "Morgan Lee", "Casey Rivera",
    "Riley Patel", "Quinn Thompson", "Avery Kim", "Cameron Singh", "Drew Anderson",
    "Muhammad Al-Rashid", "Pierre Dubois", "Lars Johansson", "Chen Wei", "Priya Sharma",
]

_HOSTNAMES = [
    "dev-workstation-01", "web-server-prod-03", "db-replica-02",
    "ci-runner-04", "ml-training-01", "staging-api-02", "cache-server-01",
    "vpn-gateway-01", "docker-host-03", "kubernetes-node-01",
    "backup-server-02", "elastic-node-01", "prometheus-02", "grafana-01", "kafka-broker-02",
]

_PASSWORD_HINTS = [
    "MyDog'sName2023!", "Sunset@Beach99", "Coffee#Lover42",
    "BlueSky!Morning7", "Winter@Snow22",
]

_FILE_PREFERENCE_POOLS = [
    [".py", ".sql", ".env"],
    [".js", ".json", ".dockerfile"],
    [".go", ".mod", ".yaml"],
    [".rs", ".toml", ".lock"],
    [".java", ".xml", ".properties"],
    [".rb", ".gemfile", ".yml"],
    [".php", ".ini", ".htaccess"],
    [".ts", ".webpack.config.js", ".npmrc"],
    [".cpp", ".h", ".cmake"],
    [".swift", ".plist", ".xcconfig"],
    [".kt", ".gradle", ".pro"],
    [".scala", ".sbt", ".conf"],
    [".r", ".rproj", ".renviron"],
    [".pl", ".cgi", ".htpasswd"],
    [".lua", ".rockspec", ".conf"],
    [".sh", ".cron", ".logrotate"],
    [".ps1", ".bat", ".reg"],
]


_COMMAND_SETS = [
    ["ls -la", "git status", "docker ps", "python manage.py"],
    ["kubectl get pods", "helm list", "terraform plan", "aws s3 ls"],
    ["npm run build", "yarn test", "docker-compose up", "curl -I localhost"],
    ["go test ./...", "make build", "redis-cli ping", "nginx -t"],
    ["cargo check", "rustc --version", "psql -l", "mongo --eval 'db.stats()'"],
    ["gradle build", "mvn test", "java -version", "systemctl status"],
    ["bundle exec rspec", "rails console", "rake db:migrate", "puma -t"],
    ["composer install", "php artisan serve", "mysql -u root -p", "apachectl configtest"],
    ["mix test", "iex -S mix", "ecto.setup", "phx.server"],
    ["stack build", "cabal test", "ghci", "hlint ."],
    ["dotnet build", "dotnet test", "az login", "gcloud init"],
    ["flutter build", "dart analyze", "pod install", "xcodebuild"],
    ["ansible-playbook", "vagrant status", "packer build", "vagrant up"],
    ["git log --oneline", "git diff HEAD~1", "git branch -a", "git remote -v"],
    ["find . -name '*.py'", "grep -r 'TODO' .", "du -sh *", "df -h"],
    ["ping -c 3 google.com", "netstat -tlnp", "ss -tlnp", "lsof -i :8080"],
    ["journalctl -u nginx", "dmesg | tail", "uptime", "whoami"],
    ["docker images", "docker network ls", "docker volume ls", "docker system df"],
    ["kubectl top nodes", "kubectl get svc", "kubectl describe pod", "kubectl logs"],
    ["terraform validate", "terraform fmt", "pulumi preview", "aws ec2 describe-instances"],
]


def _pick_ssh_banner() -> str:
    return random.choice(_SSH_BANNERS)


def _pick_http_banner() -> str:
    return random.choice(_HTTP_BANNERS)


def _pick_ftp_banner() -> str:
    return random.choice(_FTP_BANNERS)


def _pick_db_banner() -> str:
    return random.choice(_DB_BANNERS)


def _pick_identity() -> tuple[str, str, str]:
    """Pick independent name, username, and hostname to break correlation attacks."""
    name = random.choice(_PERSONA_NAMES)
    # Generate username from name but with independent randomness
    first = name.split()[0].lower()
    # Add random suffix to break 1:1 correlation
    suffixes = ["", "_dev", "_ops", "_sec", "_01", "_02", "_99", "_lab",
                "_test", "_prod", "_staging", "_qa", "_eng", "_admin",
                "_usr", "_box", "_vm", "_ws", "_srv", "_nix"]
    username = first + random.choice(suffixes)
    hostname = random.choice(_HOSTNAMES)
    return (name, username, hostname)


def _calculate_pool_entropy() -> dict:
    """Calculate Shannon entropy of identity pools."""
    import math
    name_entropy = math.log2(len(set(_PERSONA_NAMES)))
    hostname_entropy = math.log2(len(set(_HOSTNAMES)))
    total_combinations = len(set(_PERSONA_NAMES)) * 20 * len(set(_HOSTNAMES))  # 20 suffixes
    return {
        "name_bits": round(name_entropy, 2),
        "hostname_bits": round(hostname_entropy, 2),
        "total_combinations": total_combinations,
        "total_bits": round(math.log2(total_combinations), 2),
    }


# -- Enums ---------------------------------------------------------------


class HoneypotType(str, Enum):
    """Supported honeypot service types."""

    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"
    DATABASE = "database"


class InstanceStatus(str, Enum):
    """Lifecycle status of a honeypot instance."""

    PROVISIONING = "provisioning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPROMISED = "compromised"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"


# -- Pydantic Models -----------------------------------------------------


class DecoyPersona(BaseModel):
    """Decoy identity configuration for a honeypot instance."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str = "developer"  # developer | admin | db_admin | analyst
    name: str = ""
    username: str = ""
    hostname: str = ""
    password_hint: str = Field(default_factory=lambda: random.choice(_PASSWORD_HINTS))
    ssh_keys: list[str] = Field(default_factory=list)
    file_preferences: list[str] = Field(default_factory=lambda: random.choice(_FILE_PREFERENCE_POOLS).copy())
    typical_commands: list[str] = Field(
        default_factory=lambda: random.choice(_COMMAND_SETS).copy()
    )
    environment_vars: dict[str, str] = Field(
        default_factory=lambda: {
            "ENV": random.choice(["staging", "development", "testing"]),
            "SHELL": "/bin/bash",
            "TERM": random.choice(["xterm-256color", "screen", "vt100"]),
        }
    )
    fake_projects: list[str] = Field(default_factory=lambda: random.sample(
        ["api-gateway", "user-service", "payment-processor", "auth-service",
         "notification-svc", "data-pipeline", "ml-inference", "cache-layer",
         "search-index", "file-storage", "metrics-collector", "log-aggregator",
         "config-server", "feature-flags", "rate-limiter", "web-frontend",
         "mobile-api", "webhook-router", "event-bus", "task-queue"], 3))
    # -- Response-engine compatibility fields --------------------------------
    os_type: str = "linux"
    os_version: str = "Ubuntu 22.04.3 LTS"
    home_dir: str = ""
    cwd: str = ""
    shell: str = "/bin/bash"
    sudo_access: bool = True

    def model_post_init(self, __context) -> None:
        """Randomize identity after initialization if fields are unset."""
        if self.name == "" or self.username == "" or self.hostname == "":
            self.name, self.username, self.hostname = _pick_identity()
        # Auto-fill home_dir and cwd from username if not explicitly set
        if self.home_dir == "":
            self.home_dir = f"/home/{self.username}"
        if self.cwd == "":
            self.cwd = f"/home/{self.username}"


class InstanceMetrics(BaseModel):
    """Runtime metrics for a honeypot instance."""

    interaction_count: int = 0
    attacker_count: int = 0
    command_count: int = 0
    login_attempts: int = 0
    login_successes: int = 0
    uptime_seconds: float = 0.0
    last_interaction_at: datetime | None = None


class HoneypotInstance(BaseModel):
    """Represents a running (or staged) honeypot instance."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: HoneypotType = HoneypotType.SSH
    status: InstanceStatus = InstanceStatus.PROVISIONING
    persona: DecoyPersona = Field(default_factory=DecoyPersona)
    network_zone: str = "honeypot-net"
    exposed_ports: list[int] = Field(default_factory=list)
    container_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    metrics: InstanceMetrics = Field(default_factory=InstanceMetrics)
    banner: str = ""
    version_string: str = ""

    model_config = {"arbitrary_types_allowed": True}


class HoneypotConfig(BaseModel):
    """Global configuration for the HoneypotEngine."""

    name: str = "EmberHoneypot"
    port_range_start: int = 10000
    port_range_end: int = 11000
    network_isolation: bool = True
    auto_rebuild: bool = True
    max_instances: int = 50
    default_instance_ttl_minutes: int = 60
    log_db_path: str = "./honeypot_logs.db"
    enable_metrics: bool = True

    @field_validator("port_range_end")
    @classmethod
    def validate_port_range(cls, v: int, info: Any) -> int:
        start = info.data.get("port_range_start", 10000)
        if v <= start:
            raise ValueError("port_range_end must be greater than port_range_start")
        if v - start > 10000:
            raise ValueError("port range span must not exceed 10000 ports")
        return v


# -- HoneypotEngine ------------------------------------------------------


class HoneypotEngine:
    """Orchestrates honeypot instances: spawn, manage, destroy.

    This is the central controller for the EmberHoneypot platform.
    It manages a fleet of emulated services (SSH, HTTP, etc.) and
    tracks their lifecycle from provisioning through destruction.
    """

    def __init__(self, config: HoneypotConfig) -> None:
        self.config = config
        self._instances: dict[str, HoneypotInstance] = {}
        self._port_allocations: dict[int, str] = {}  # port -> instance_id
        self._next_port: int = config.port_range_start
        self._lock = asyncio.Lock()
        self._running = False

    # -- Lifecycle --------------------------------------------------------

    async def start(self) -> None:
        """Start the engine and restore any persisted instances."""
        self._running = True
        # In a full implementation, this would restore instances from DB
        # and restart their emulated services.

    async def stop(self) -> None:
        """Stop all running instances gracefully."""
        self._running = False
        for instance in list(self._instances.values()):
            if instance.status in (InstanceStatus.ACTIVE, InstanceStatus.PAUSED):
                await self.destroy_instance(instance.id)

    # -- Instance Management ----------------------------------------------

    async def spawn_instance(
        self,
        persona: DecoyPersona,
        service_type: HoneypotType = HoneypotType.SSH,
        network_zone: str = "honeypot-net",
    ) -> HoneypotInstance:
        """Create and start a new honeypot instance.

        Args:
            persona: Decoy identity configuration.
            service_type: Type of service to emulate.
            network_zone: Network segment for the instance.

        Returns:
            The newly created HoneypotInstance.

        Raises:
            RuntimeError: If the engine is not running or max instances reached.
        """
        if not self._running:
            raise RuntimeError("Engine is not running. Call start() first.")

        async with self._lock:
            if len(self._instances) >= self.config.max_instances:
                raise RuntimeError(
                    f"Maximum instance limit ({self.config.max_instances}) reached"
                )

            # Allocate port
            port = self._allocate_port()

            # Build instance
            instance = HoneypotInstance(
                type=service_type,
                status=InstanceStatus.PROVISIONING,
                persona=persona,
                network_zone=network_zone,
                exposed_ports=[port],
            )

            # Set randomized banner/version based on service type
            instance = self._configure_service_basics(instance)

            # Store and activate
            self._instances[instance.id] = instance
            self._port_allocations[port] = instance.id
            instance.status = InstanceStatus.ACTIVE

            # Anti-fingerprinting: realistic provisioning delay
            self._response_delay("medium")

            return instance

    async def destroy_instance(self, instance_id: str) -> None:
        """Tear down a honeypot instance gracefully.

        Args:
            instance_id: UUID of the instance to destroy.

        Raises:
            KeyError: If the instance does not exist.
        """
        async with self._lock:
            instance = self._instances.get(instance_id)
            if instance is None:
                raise KeyError(f"Instance {instance_id} not found")

            instance.status = InstanceStatus.DESTROYING

            # Anti-fingerprinting: realistic teardown delay
            self._response_delay("medium")

            # Free ports
            for port in instance.exposed_ports:
                self._port_allocations.pop(port, None)

            instance.status = InstanceStatus.DESTROYED
            del self._instances[instance_id]

    async def pause_instance(self, instance_id: str) -> HoneypotInstance:
        """Pause a running instance (stop accepting connections but preserve state).

        Args:
            instance_id: UUID of the instance to pause.

        Returns:
            The updated instance.

        Raises:
            KeyError: If the instance does not exist.
            RuntimeError: If the instance is not active.
        """
        async with self._lock:
            instance = self._instances.get(instance_id)
            if instance is None:
                raise KeyError(f"Instance {instance_id} not found")
            if instance.status != InstanceStatus.ACTIVE:
                raise RuntimeError(f"Cannot pause instance in {instance.status} state")

            instance.status = InstanceStatus.PAUSED
            self._response_delay("low")
            return instance

    async def resume_instance(self, instance_id: str) -> HoneypotInstance:
        """Resume a paused instance.

        Args:
            instance_id: UUID of the instance to resume.

        Returns:
            The updated instance.

        Raises:
            KeyError: If the instance does not exist.
            RuntimeError: If the instance is not paused.
        """
        async with self._lock:
            instance = self._instances.get(instance_id)
            if instance is None:
                raise KeyError(f"Instance {instance_id} not found")
            if instance.status != InstanceStatus.PAUSED:
                raise RuntimeError(f"Cannot resume instance in {instance.status} state")

            instance.status = InstanceStatus.ACTIVE
            self._response_delay("low")
            return instance

    # -- Queries ----------------------------------------------------------

    async def list_instances(
        self,
        status: InstanceStatus | None = None,
    ) -> list[HoneypotInstance]:
        """List all instances, optionally filtered by status.

        Args:
            status: If provided, only return instances with this status.

        Returns:
            List of matching HoneypotInstance objects.
        """
        self._response_delay("low")
        instances = list(self._instances.values())
        if status:
            instances = [i for i in instances if i.status == status]
        return instances

    async def get_instance(self, instance_id: str) -> HoneypotInstance | None:
        """Get a single instance by ID.

        Args:
            instance_id: UUID of the instance.

        Returns:
            The instance, or None if not found.
        """
        self._response_delay("low")
        return self._instances.get(instance_id)

    # -- Helpers ----------------------------------------------------------

    @staticmethod
    def _realistic_delay(base: float = 0.1, sigma: float = 0.5) -> float:
        """Log-normal delay matching real system response times.

        Real systems have: fast mode (~50ms), slow tail (up to 2s).
        Log-normal: mean = base * exp(sigma^2/2), right-skewed.
        """
        delay = base * random.lognormvariate(0, sigma)
        return min(delay, 2.0)  # Cap at 2 seconds

    @staticmethod
    def _response_delay(complexity: str = "low") -> None:
        """Apply realistic timing jitter to responses.

        Args:
            complexity: One of 'ssh_handshake', 'command', 'file_listing',
                       'auth_check', 'low', 'medium', 'high'.
        """
        base_map = {
            "ssh_handshake": 0.15,
            "command": 0.05,
            "file_listing": 0.08,
            "auth_check": 0.03,
            "low": 0.05,
            "medium": 0.08,
            "high": 0.15,
        }
        base = base_map.get(complexity, 0.05)
        time.sleep(HoneypotEngine._realistic_delay(base=base, sigma=0.8))

    def _allocate_port(self) -> int:
        """Allocate the next available port in the configured range."""
        start_port = self._next_port
        port_count = (
            self.config.port_range_end - self.config.port_range_start + 1
        )
        for offset in range(port_count):
            candidate = (
                self.config.port_range_start
                + (start_port - self.config.port_range_start + offset)
                % port_count
            )
            if candidate not in self._port_allocations:
                self._next_port = candidate + 1
                if self._next_port > self.config.port_range_end:
                    self._next_port = self.config.port_range_start
                return candidate
        raise RuntimeError("No available ports in configured range")

    def _configure_service_basics(self, instance: HoneypotInstance) -> HoneypotInstance:
        """Set randomized banners and version strings based on service type.

        Banners are selected from pools to prevent fingerprinting.
        """
        match instance.type:
            case HoneypotType.SSH:
                instance.banner = _pick_ssh_banner()
                instance.version_string = instance.banner.split("_")[1].split()[0] if "_" in instance.banner else "OpenSSH_8.9"
            case HoneypotType.HTTP:
                instance.banner = _pick_http_banner()
                instance.version_string = instance.banner.split(": ")[1] if ": " in instance.banner else "nginx/1.24.0"
            case HoneypotType.FTP:
                instance.banner = _pick_ftp_banner()
                instance.version_string = instance.banner.split()[1] if len(instance.banner.split()) > 1 else "Pure-FTPd"
            case HoneypotType.DATABASE:
                instance.banner = _pick_db_banner()
                instance.version_string = instance.banner.split(" on ")[0] if " on " in instance.banner else "PostgreSQL_14.10"
        return instance

    @property
    def is_running(self) -> bool:
        """Whether the engine is currently running."""
        return self._running

    @property
    def active_instance_count(self) -> int:
        return len(self._instances)

    # -- Health Check --

    async def health_check(self) -> dict:
        """Return health status of the honeypot engine.

        Returns:
            Dict with keys: healthy (bool), is_running,
            instance_count, config_valid, max_instances.
        """
        try:
            return {
                "healthy": True,
                "name": "engine",
                'is_running': self._running,
                "instance_count": len(self._instances),
                "config_valid": self.config is not None,
                "max_instances": getattr(self.config, "max_instances", 100),
                "detail": (
                    f"Engine managing {len(self._instances)} instances, "
                    f"running={self._running}"
                ),
            }
        except Exception as exc:
            return {
                "healthy": False,
                "name": "engine",
                "is_running": getattr(self, "_running", False),
                "instance_count": 0,
                "config_valid": False,
                "max_instances": 100,
                "detail": f"Engine health check failed: {exc}",
            }

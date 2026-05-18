"""Decoy Persona -- Library of pre-built server identities."""

from __future__ import annotations

import os
import random
import uuid
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

# ── SSH Banner Pool for entropy injection ───────────────────────────────
# Randomly selected per persona instance to prevent fingerprinting.
_SSH_BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu0.4",
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3",
    "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
    "SSH-2.0-OpenSSH_8.0p1 Fedora-11.fc36",
    "SSH-2.0-OpenSSH_9.4p1 Fedora-11.fc39",
    "SSH-2.0-OpenSSH_8.8p1 Debian-5+deb11u1",
    "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7",
    "SSH-2.0-OpenSSH_8.7p1 Fedora-11.fc35",
    "SSH-2.0-OpenSSH_9.5p1 Debian-6+b1",
]

# ── Persona Identity Pools ──────────────────────────────────────────────
# Randomly selected to make every persona instance unique.
_PERSONA_NAMES = [
    # Original 20
    "Alex Chen", "Jordan Smith", "Taylor Wong", "Morgan Lee", "Casey Rivera",
    "Riley Patel", "Quinn Thompson", "Avery Kim", "Cameron Singh", "Drew Anderson",
    "Reese Nakamura", "Parker Silva", "Sawyer O'Brien", "Hayden Mueller", "Emery Johansson",
    "Dakoro Tanaka", "Lennon Garcia", "Sage Fernandez", "Kai Andersen", "Nico Rossi",
    # 80 more diverse names
    "Muhammad Al-Rashid", "Pierre Dubois", "Lars Johansson", "Hans Mueller",
    "Ivan Petrov", "Chen Wei", "Yuki Tanaka", "Priya Sharma", "Fatima Al-Hassan",
    "Olga Kuznetsova", "Diego Martinez", "Aisha Okonkwo", "Bjorn Eriksson",
    "Sofia Papadopoulos", "Amir Hosseini", "Chloe Dubois", "Rajesh Kumar",
    "Ingrid Svensson", "Mateo Rossi", "Yuna Park", "Ahmed Hassan", "Elena Popov",
    "Takeshi Yamamoto", "Ananya Reddy", "Liam O'Brien", "Zara Khan",
    "Nikolai Volkov", "Mei Lin", "Omar Farooq", "Isabella Romano",
    "Klaus Weber", "Sakura Watanabe", "Abdul Rahman", "Clara Fischer",
    "Ravi Patel", "Emma Johansson", "Jin-Ho Kim", "Leila Moussa",
    "Sven Lindqvist", "Aanya Gupta", "Tariq Aziz", "Bridget O'Connor",
    "Friedrich Bauer", "Hana Suzuki", "Karim Benali", "Megan Williams",
    "Dmitri Sokolov", "Priya Nair", "Luca Bianchi", "Yasmin Abadi",
    "Henrik Nilsson", "Anika Sharma", "Oleg Morozov", "Siobhan Murphy",
    "Rafael Santos", "Nadia Volkov", "Kenji Mori", "Freya Olsen",
    "Viktor Kuzmin", "Amara Okafor", "Gustav Lindberg", "Mei-Hua Chen",
    "Ibrahim Kaya", "Nora Jansen", "Sergei Volkov", "Adebayo Olumide",
    "Lena Fischer", "Tariq Mahmoud", "Ines Alvarez", "Bjorn Holm",
    "Zara Okafor", "Ravi Shankar", "Klara Novak", "Yusuf Demir",
]

_HOSTNAMES = [
    # Original 16 (preserved and expanded)
    "localhost", "dev-workstation-01", "web-server-prod-03", "db-replica-02",
    "ci-runner-04", "ml-training-01", "staging-api-02", "analytics-node-03",
    "cache-server-01", "monitoring-02", "vpn-gateway-01", "ubuntu-server-02",
    "docker-host-03", "kubernetes-node-01", "backup-server-02", "jenkins-agent-03",
    # 84 more realistic hostnames
    "elastic-node-01", "prometheus-02", "grafana-dashboard-01", "kafka-broker-02",
    "redis-cluster-03", "ws-lp-nyc-42", "srv-db-sf-17", "vm-dev-chi-08", "box-qa-atl-33",
    "host-prod-sea-91", "node-ml-bos-12", "web-fe-den-55", "api-be-por-77",
    "core-svc-aus-23", "edge-cdn-dal-09", "gw-vpn-mia-66", "px-proxy-lax-41",
    "fs-nfs-ord-88", "lb-hap-nyc-14", "mq-rmq-sjc-29", "es-search-blr-73",
    "pg-primary-ams-36", "mg-replica-sin-58", "zk-ensemble-fra-21",
    "consul-server-lon-47", "nomad-client-tyo-82", "vault-server-syd-15",
    "tf-state-backend-ber-63", "helm-repo-sto-38", "argocd-server-hel-94",
    "istio-pilot-mtl-27", "linkerd-proxy-osl-51", "spire-server-mad-76",
    "opa-gatekeeper-hkg-19", "falco-agent-dub-64", "trivy-scanner-prg-86",
    "velero-backup-bud-44", "external-dns-waw-11", "cert-manager-zrh-96",
    "ingress-nginx-bru-31", "flagger-canary-edi-69", "keda-operator-rom-53",
    "dapr-sidecar-vie-24", "knative-serving-cph-78", "tekton-pipeline-msp-17",
    "drone-runner-arn-92", "spinnaker-gate-lis-37", "ambassador-edge-cgn-59",
    "kong-gateway-cpt-83", "haproxy-lb-aku-45", "traefik-proxy-rno-13",
    "caddy-web-bue-97", "lighttpd-static-mde-26", "varnish-cache-khh-72",
    "squid-proxy-ctx-57", "nats-server-gye-39", "pulsar-broker-uio-85",
    "mqtt-broker-cur-16", "coap-gateway-bze-68", "grpc-server-bgi-22",
    "thrift-node-anu-95", "avro-registry-gcm-48", "protobuf-svc-mru-74",
    "graphql-faas-cgk-32", "rest-api-pod-gdl-87", "soap-svc-bog-28",
    "odata-server-cwb-61", "websocket-svc-for-43", "sse-node-sdu-18",
    "webhook-receiver-ctg-99", "callback-svc-clo-35", "cron-runner-baq-75",
    "queue-worker-bcn-52", "event-source-cmn-14", "stream-processor-sal-89",
    "batch-job-mga-41", "dag-runner-lpb-67", "pipeline-agent-ccs-23",
    "stage-worker-mvd-93", "scene-node-asu-46", "render-farm-scl-71",
    "compute-node-uio-11", "gpu-worker-pty-98", "tpu-node-geo-34",
    "fpga-host-mnl-56", "asic-miner-cmb-81", "qpu-node-fih-19",
    "neuromorphic-npe-62", "analog-sim-nov-77", "wetware-node-ppt-25",
]


class VulnerabilityProfile(BaseModel):
    """Known vulnerability in a persona."""
    cve_id: str = ""
    name: str
    description: str
    severity: str = "medium"
    exploitable: bool = True
    exploit_hint: str = ""


def _pick_ssh_banner() -> str:
    """Return a randomly selected SSH banner to prevent fingerprinting."""
    return random.choice(_SSH_BANNERS)


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


class DecoyPersonaConfig(BaseModel):
    """Full configuration for a decoy persona."""
    name: str
    description: str
    role: str = "developer"
    username: str = "admin"
    password: str = ""
    hostname: str = "localhost"
    os_type: str = "linux"
    os_version: str = "Ubuntu 22.04.3 LTS"
    shell: str = "/bin/bash"
    home_dir: str = "/home/admin"
    working_directory: str = "/home/admin"
    sudo_access: bool = True
    ssh_enabled: bool = True
    ssh_port: int = 22
    ssh_banner: str = Field(default_factory=_pick_ssh_banner)
    http_enabled: bool = False
    http_port: int = 80
    http_server_header: str = ""
    services: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    fake_files: list[str] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityProfile] = Field(default_factory=list)
    fake_credentials: list[dict[str, str]] = Field(default_factory=list)
    environment_vars: dict[str, str] = Field(default_factory=dict)
    fake_projects: list[str] = Field(default_factory=list)
    typical_commands: list[str] = Field(default_factory=list)
    bait_data: dict[str, Any] = Field(default_factory=dict)


class DecoyPersona(ABC):
    """Abstract base for decoy personas."""

    def __init__(self) -> None:
        self._config = self.get_config()

    @abstractmethod
    def get_config(self) -> DecoyPersonaConfig:
        ...

    @property
    def name(self) -> str: return self._config.name
    @property
    def description(self) -> str: return self._config.description
    @property
    def username(self) -> str: return self._config.username
    @property
    def password(self) -> str: return self._config.password
    @property
    def hostname(self) -> str: return self._config.hostname
    @property
    def os_type(self) -> str: return self._config.os_type
    @property
    def os_version(self) -> str: return self._config.os_version
    @property
    def services(self) -> list[str]: return self._config.services
    @property
    def open_ports(self) -> list[int]: return self._config.open_ports
    @property
    def vulnerabilities(self) -> list[VulnerabilityProfile]: return self._config.vulnerabilities

    def get_vuln_by_name(self, n: str) -> VulnerabilityProfile | None:
        for v in self._config.vulnerabilities:
            if n.lower() in v.name.lower():
                return v
        return None

    def get_vuln_by_cve(self, c: str) -> VulnerabilityProfile | None:
        for v in self._config.vulnerabilities:
            if v.cve_id.upper() == c.upper():
                return v
        return None

    def to_dict(self) -> dict[str, Any]:
        return self._config.model_dump()


class LegacyAPIPersona(DecoyPersona):
    """Old REST API with known CVEs."""
    def get_config(self) -> DecoyPersonaConfig:
        return DecoyPersonaConfig(
            name="LegacyAPIPersona", description="Old REST API gateway running outdated Node.js with known CVEs",
            # SECURITY: This is an INTENTIONAL test password.
            # It exists to attract attackers, not protect real systems.
            # See: https://docs.server-guard.dev/test-passwords
            role="api_gateway", username="apiadmin", password=os.environ.get("SRV_DECOY_API_ADMIN", "apiadmin123"), hostname="api-gateway-01",
            os_version="Ubuntu 18.04.6 LTS", home_dir="/home/apiadmin", working_directory="/opt/api-gateway",
            ssh_banner=_pick_ssh_banner(),
            http_enabled=True, http_port=8080, http_server_header="Server: nginx/1.14.0 (Ubuntu)",
            services=["ssh", "nginx", "node", "mongodb", "redis"],
            open_ports=[22, 80, 8080, 3000, 6379, 27017],
            fake_files=["/opt/api-gateway/package.json", "/opt/api-gateway/.env", "/opt/api-gateway/swagger.yaml"],
            vulnerabilities=[
                VulnerabilityProfile(cve_id="CVE-2021-23337", name="Node.js lodash Prototype Pollution",
                                     description="lodash vulnerable to prototype pollution.", severity="HIGH",
                                     exploit_hint="lodash 4.17.4 in package.json"),
                VulnerabilityProfile(name="MongoDB Unauthenticated Access",
                                     description="MongoDB without authentication.", severity="CRITICAL",
                                     exploit_hint="MongoDB on 0.0.0.0:27017 with no auth"),
                VulnerabilityProfile(name="Hardcoded API Keys",
                                     description="Credentials in plaintext .env.", severity="HIGH",
                                     exploit_hint="cat /opt/api-gateway/.env"),
            ],
            fake_credentials=[
                {"username": "apiadmin", "password": "apiadmin123", "role": "admin"},
                {"username": "apiuser", "password": "Welcome2024!", "role": "user"},
            ],
            environment_vars={"NODE_ENV": "production", "PORT": "8080",
                              "MONGODB_URI": "mongodb://localhost:27017/api_production",
                              "JWT_SECRET": "super_secret_jwt", "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
            fake_projects=["api-gateway-v2", "legacy-auth-service"],
            typical_commands=["npm start", "pm2 logs", "cat .env", "mongo"],
            bait_data={"api_endpoints": [{"path": "/api/v1/users", "auth": "bearer"},
                                          {"path": "/api/v1/admin/config", "auth": "none"}]},)


class ForgottenJenkinsPersona(DecoyPersona):
    """Exposed Jenkins with weak credentials."""
    def get_config(self) -> DecoyPersonaConfig:
        return DecoyPersonaConfig(
            name="ForgottenJenkinsPersona", description="Exposed Jenkins 2.138.1 with Script Console RCE",
            # SECURITY: This is an INTENTIONAL test password.
            # It exists to attract attackers, not protect real systems.
            # See: https://docs.server-guard.dev/test-passwords
            role="ci_server", username="admin", password=os.environ.get("SRV_DECOY_JENKINS_ADMIN", "admin"), hostname="ci-jenkins-01",
            os_version="CentOS Linux 7.9", home_dir="/var/lib/jenkins", working_directory="/var/lib/jenkins",
            sudo_access=False, ssh_banner=_pick_ssh_banner(),
            http_enabled=True, http_port=8080, http_server_header="Server: Jetty(9.4.z-SNAPSHOT)",
            services=["ssh", "jenkins", "java", "docker"], open_ports=[22, 8080, 50000],
            fake_files=["/var/lib/jenkins/config.xml", "/var/lib/jenkins/credentials.xml",
                        "/var/lib/jenkins/secrets/master.key"],
            vulnerabilities=[
                VulnerabilityProfile(cve_id="CVE-2019-1003000", name="Jenkins Script Security Escape",
                                     description="Sandbox escape via constructor injection.", severity="CRITICAL",
                                     exploit_hint="Script Console at /script allows Groovy RCE"),
                VulnerabilityProfile(name="Default Admin Credentials",
                                     description="Admin uses default password.", severity="CRITICAL"),
                VulnerabilityProfile(cve_id="CVE-2017-1000353", name="Jenkins Deserialization RCE",
                                     description="RCE via Jenkins CLI deserialization.", severity="CRITICAL"),
            ],
            fake_credentials=[{"username": "admin", "password": "admin", "role": "admin"},
                              {"username": "deploy", "password": "deploy", "role": "deployer"}],
            environment_vars={"JENKINS_HOME": "/var/lib/jenkins", "JAVA_HOME": "/usr/lib/jvm/java-8-openjdk"},
            fake_projects=["payment-gateway-prod", "auth-service", "security-scan"],
            typical_commands=["cat config.xml", "ls jobs/", "docker ps"],
            bait_data={"build_history": [{"job": "payment-gateway-prod", "status": "SUCCESS"},
                                          {"job": "auth-service", "status": "FAILURE"}]},)


class LeakyS3Persona(DecoyPersona):
    """Misconfigured S3 storage with public listings."""
    def get_config(self) -> DecoyPersonaConfig:
        return DecoyPersonaConfig(
            name="LeakyS3Persona", description="Misconfigured MinIO with public bucket listings",
            # SECURITY: This is an INTENTIONAL test password.
            # It exists to attract attackers, not protect real systems.
            # See: https://docs.server-guard.dev/test-passwords
            role="storage_server", username="minioadmin", password=os.environ.get("SRV_DECOY_MINIO_ADMIN", "minioadmin"), hostname="storage-minio-01",
            os_version="Ubuntu 20.04.6 LTS", home_dir="/home/minio", working_directory="/data",
            ssh_banner=_pick_ssh_banner(),
            http_enabled=True, http_port=9000, http_server_header="Server: MinIO",
            services=["ssh", "minio", "nginx"], open_ports=[22, 80, 9000, 9001],
            fake_files=["/data/backups/", "/data/finance/", "/data/configs/", "/data/customers/"],
            vulnerabilities=[
                VulnerabilityProfile(name="Public Bucket Policy", description="Public read access allowed.",
                                     severity="HIGH", exploit_hint="Principal: * with s3:GetObject"),
                VulnerabilityProfile(name="Default MinIO Credentials", description="Default minioadmin/minioadmin.",
                                     severity="CRITICAL", exploit_hint="Console at :9001"),
            ],
            fake_credentials=[{"username": "minioadmin", "password": "minioadmin", "role": "admin"}],
            environment_vars={"MINIO_ROOT_USER": "minioadmin", "MINIO_ROOT_PASSWORD": "minioadmin"},
            fake_projects=["data-lake", "backup-archive"],
            typical_commands=["mc ls storage/", "curl http://localhost:9000/backups/"],
            bait_data={"buckets": [{"name": "backups", "objects": ["database_dump.sql.gz (2.3 GB)"]},
                                    {"name": "finance", "objects": ["Q1_2024_report.xlsx (4.2 MB)"]}]},)


class ChattyDBPersona(DecoyPersona):
    """PostgreSQL with verbose logging and weak DBA credentials."""
    def get_config(self) -> DecoyPersonaConfig:
        return DecoyPersonaConfig(
            name="ChattyDBPersona", description="PostgreSQL 12 with verbose logging and weak DBA credentials",
            # SECURITY: This is an INTENTIONAL test password.
            # It exists to attract attackers, not protect real systems.
            # See: https://docs.server-guard.dev/test-passwords
            role="database_server", username="postgres", password=os.environ.get("SRV_DECOY_POSTGRES", "postgres123"), hostname="db-primary-01",
            os_version="Ubuntu 20.04.6 LTS", home_dir="/var/lib/postgresql",
            working_directory="/var/lib/postgresql",
            ssh_banner=_pick_ssh_banner(),
            services=["ssh", "postgresql", "pgbouncer"], open_ports=[22, 5432, 6432],
            fake_files=["/etc/postgresql/12/main/postgresql.conf", "/var/lib/postgresql/.pgpass",
                        "/opt/scripts/db_backup.sh"],
            vulnerabilities=[
                VulnerabilityProfile(name="Weak DBA Password", description="Weak postgres password.",
                                     severity="CRITICAL", exploit_hint="psql -U postgres accepts postgres123"),
                VulnerabilityProfile(cve_id="CVE-2019-9193", name="PostgreSQL COPY RCE",
                                     description="COPY FROM PROGRAM allows RCE.", severity="CRITICAL",
                                     exploit_hint="COPY (SELECT '') TO PROGRAM 'id'"),
                VulnerabilityProfile(name="Backup Script Credentials",
                                     description="Hardcoded credentials in backup script.", severity="HIGH"),
            ],
            fake_credentials=[{"username": "postgres", "password": "postgres123", "role": "superuser"},
                              {"username": "app_user", "password": "app_password_2024", "role": "read_write"}],
            environment_vars={"PGDATA": "/var/lib/postgresql/12/main", "PGUSER": "postgres",
                              "PGPASSWORD": "postgres123"},
            fake_projects=["production_db", "analytics_warehouse"],
            typical_commands=["psql -U postgres -l", "cat postgresql.conf"],
            bait_data={"databases": [{"name": "app_production", "tables": ["users", "orders"]},
                                      {"name": "hr_system", "tables": ["employees", "salaries"]}]},)


class DevServerPersona(DecoyPersona):
    """Django dev server with DEBUG=True exposed."""
    def get_config(self) -> DecoyPersonaConfig:
        return DecoyPersonaConfig(
            name="DevServerPersona", description="Django dev server with DEBUG=True and Werkzeug debugger",
            # SECURITY: This is an INTENTIONAL test password.
            # It exists to attract attackers, not protect real systems.
            # See: https://docs.server-guard.dev/test-passwords
            role="dev_server", username="developer", password=os.environ.get("SRV_DECOY_DEVELOPER", "developer"), hostname="dev-server-01",
            home_dir="/home/developer", working_directory="/home/developer/projects/myapp",
            ssh_banner=_pick_ssh_banner(),
            http_enabled=True, http_port=8000, http_server_header="WSGIServer/0.2 CPython/3.10.12",
            services=["ssh", "django", "python", "sqlite", "redis"], open_ports=[22, 8000, 6379],
            fake_files=["/home/developer/projects/myapp/settings.py",
                        "/home/developer/projects/myapp/.env",
                        "/home/developer/projects/myapp/db.sqlite3",
                        "/home/developer/.ssh/id_rsa"],
            vulnerabilities=[
                VulnerabilityProfile(name="Django DEBUG Mode", description="DEBUG=True exposes stack traces.",
                                     severity="HIGH", exploit_hint="Any 404 reveals stack trace"),
                VulnerabilityProfile(name="Werkzeug Debugger", description="Debugger without PIN protection.",
                                     severity="CRITICAL", exploit_hint="/__console__ allows Python execution"),
                VulnerabilityProfile(name="SSH Key in Home", description="Unencrypted SSH private key.",
                                     severity="HIGH"),
            ],
            fake_credentials=[{"username": "developer", "password": "developer", "role": "developer"},
                              {"username": "admin", "password": "admin12345", "role": "admin"}],
            environment_vars={"DEBUG": "True", "SECRET_KEY": "django-insecure-change-me",
                              "DATABASE_URL": "sqlite:///db.sqlite3"},
            fake_projects=["customer-portal", "internal-dashboard"],
            typical_commands=["python manage.py runserver", "cat settings.py"],
            bait_data={"django_admin_url": "/admin/", "werkzeug_console": "/__console__/"},)


class VPNPortalPersona(DecoyPersona):
    """OpenVPN with predictable session tokens."""
    def get_config(self) -> DecoyPersonaConfig:
        return DecoyPersonaConfig(
            name="VPNPortalPersona", description="OpenVPN Access Server with predictable session tokens",
            # SECURITY: This is an INTENTIONAL test password.
            # It exists to attract attackers, not protect real systems.
            # See: https://docs.server-guard.dev/test-passwords
            role="vpn_gateway", username="vpnuser", password=os.environ.get("SRV_DECOY_VPN", "vpnuser2024!"), hostname="vpn-gateway-01",
            os_version="Ubuntu 20.04.6 LTS", home_dir="/home/vpnuser", working_directory="/home/vpnuser",
            sudo_access=False, ssh_banner=_pick_ssh_banner(),
            http_enabled=True, http_port=943, http_server_header="Server: OpenVPN-AS",
            services=["ssh", "openvpn-as", "nginx"], open_ports=[22, 443, 943, 945],
            fake_files=["/usr/local/openvpn_as/etc/config.json", "/home/vpnuser/client.ovpn"],
            vulnerabilities=[
                VulnerabilityProfile(name="Predictable Session Tokens",
                                     description="Weak randomness in token generation.", severity="HIGH",
                                     exploit_hint="SESSION_<timestamp>_<increment>"),
                VulnerabilityProfile(name="Weak MFA", description="Hardcoded TOTP secret for all users.",
                                     severity="CRITICAL", exploit_hint="TOTP secret: JBSWY3DPEHPK3PXP"),
            ],
            fake_credentials=[{"username": "vpnuser", "password": "vpnuser2024!", "role": "user"},
                              {"username": "admin", "password": "admin@openvpn", "role": "admin"}],
            environment_vars={"OVPN_CONFIG": "/usr/local/openvpn_as/etc/config.json"},
            fake_projects=["remote-access"],
            typical_commands=["cat config.json", "cat client.ovpn"],
            bait_data={"connected_users": [{"username": "alice.smith", "ip": "10.8.0.2"}],
                        "vpn_network": "10.8.0.0/24"},)

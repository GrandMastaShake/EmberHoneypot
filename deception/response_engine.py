"""Response Engine -- Crafts convincing responses to attacker actions."""

from __future__ import annotations

import os
import random
import string
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ..core.engine import DecoyPersona


_LINUX_TEMPLATES: dict[str, list[str]] = {
    "pwd": ["{cwd}"],
    "whoami": ["{username}"],
    "id": ["uid={uid}({username}) gid={gid}({username}) groups={gid}({username}),27(sudo)"],
    "hostname": ["{hostname}"],
    "uname": ["Linux", "Linux {hostname} 5.15.0-76-generic #83-Ubuntu SMP {date} x86_64 x86_64 x86_64 GNU/Linux"],
    "ps": ["  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  512 ?        00:00:01 sshd\n  834 ?        00:00:02 nginx\n  901 ?        00:00:01 postgresql\n 1056 ?        00:00:00 redis-server\n {bpid} pts/0    00:00:00 bash\n {ppid} pts/0    00:00:00 ps"],
    "df": ["Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/sda1      102556364 23456123  78900241  23% /\n/dev/sdb1      512000000 123456789 388543211  24% /data"],
    "free": ["              total        used        free      shared  buff/cache   available\nMem:        {mt}       {mu}       {mf}        {ms}       {mc}       {ma}\nSwap:       {st}            0       {sf}"],
    "netstat": ["Active Internet connections\nProto Recv-Q Send-Q Local Address    Foreign Address    State\ntcp   0      0      0.0.0.0:80       0.0.0.0:*          LISTEN\ntcp   0      0      0.0.0.0:443      0.0.0.0:*          LISTEN\ntcp   0      0      127.0.0.1:5432   0.0.0.0:*          LISTEN\ntcp   0      0      127.0.0.1:6379   0.0.0.0:*          LISTEN"],
    "uptime": [" {time} up {days} days, {hours}:{mins},  {users} user,  load average: {l1}, {l5}, {l15}"],
    "env": ["HOME={home}\nUSER={username}\nSHELL={shell}\nPWD={cwd}\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=en_US.UTF-8"],
}

_HTTP_ERRORS: dict[int, str] = {
    400: "<html><title>400 Bad Request</title><body><h1>Bad Request</h1><hr><address>{server}</address></body></html>",
    401: "<html><title>401 Unauthorized</title><body><h1>Unauthorized</h1><hr><address>{server}</address></body></html>",
    403: "<html><title>403 Forbidden</title><body><h1>Forbidden</h1><p>{path}</p><hr><address>{server}</address></body></html>",
    404: "<html><title>404 Not Found</title><body><h1>Not Found</h1><p>{path}</p><hr><address>{server}</address></body></html>",
    500: "<html><title>500 Internal Server Error</title><body><h1>Internal Server Error</h1><hr><address>{server}</address></body></html>",
}

_BANNERS: dict[str, list[str]] = {
    "ssh": ["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "SSH-2.0-OpenSSH_8.2p1"],
    "http": ["Server: nginx/1.18.0 (Ubuntu)", "Server: Apache/2.4.41"],
    "ftp": ["220 (vsFTPd 3.0.3)", "220 Welcome to Pure-FTPd"],
    "smtp": ["220 mail.acme.corp ESMTP Postfix", "220 mail.acme.corp Microsoft ESMTP"],
    "redis": ["+PONG\r\n", "-NOAUTH Authentication required.\r\n"],
    "telnet": ["\r\nWelcome to {hostname}\r\n{hostname} login: "],
}


class ResponseEngine:
    """Craft realistic but harmless responses."""

    def __init__(self, persona: DecoyPersona | None = None, realism: str = "high", seed: int | None = None) -> None:
        self.persona = persona or DecoyPersona()
        self.realism = realism
        self._rnd = random.Random(seed)

    def craft_response(self, request: str, persona: DecoyPersona | None = None) -> str:
        p = persona or self.persona
        parts = request.strip().lower().split()
        if not parts:
            return ""
        cmd = parts[0]
        args = parts[1:]
        if cmd in ("ls", "dir"):
            return self._ls(p)
        if cmd == "cat" and args:
            return self._cat(args[0], p)
        tmpl = _LINUX_TEMPLATES.get(cmd)
        if tmpl:
            return self._fill(self._rnd.choice(tmpl), p)
        if cmd == "ifconfig" or cmd == "ip":
            return self._ifconfig(p)
        if cmd == "find":
            return self._find(args, p)
        if cmd == "echo":
            return " ".join(args)
        if cmd in ("wget", "curl"):
            return self._dl()
        if cmd == "history":
            return self._hist()
        if cmd == "sudo":
            return f"{p.username} is not in the sudoers file.  This incident will be reported."
        if cmd in ("which", "whereis"):
            return f"/usr/bin/{args[0] if args else cmd}"
        return f"bash: {cmd}: command not found"

    def add_latency(self, base: float, var: float = 0.2) -> float:
        if self.realism == "low":
            d = base * 0.1
        elif self.realism == "medium":
            d = base * (1.0 + self._rnd.uniform(-var, var))
        else:
            d = base * (1.0 + self._rnd.uniform(-var, var * 2))
            if self._rnd.random() < 0.05:
                d += self._rnd.uniform(0.5, 2.0)
        d = max(0.01, d)
        time.sleep(d)
        return d

    def inject_errors(self, response: str, rate: float = 0.02) -> str:
        if self._rnd.random() > rate:
            return response
        errs = ["bash: {cmd}: Permission denied", "bash: {cmd}: No such file or directory",
                "bash: {cmd}: command not found", "Connection timed out"]
        ctx = response.split()[0] if response else "unknown"
        return self._rnd.choice(errs).format(cmd=ctx)

    def match_banner(self, service: str, version: str = "") -> str:
        banners = _BANNERS.get(service, [""])
        b = self._rnd.choice(banners)
        return b.format(hostname=self.persona.hostname) if "{hostname}" in b else b

    def craft_http_response(self, code: int = 200, path: str = "/", server: str = "nginx/1.18.0") -> str:
        return _HTTP_ERRORS.get(code, _HTTP_ERRORS.get(500, "Error")).format(path=path, server=server)

    def craft_shell_prompt(self, persona: DecoyPersona | None = None) -> str:
        p = persona or self.persona
        cd = p.cwd.replace(p.home_dir, "~") if p.cwd.startswith(p.home_dir) else p.cwd
        return f"{p.username}@{p.hostname}:{cd}$ "

    def _ls(self, p: DecoyPersona) -> str:
        return (f"drwxr-xr-x 3 {p.username} {p.username} 4096 Jun 15 10:23 .\n"
                f"drwxr-xr-x 5 root   root   4096 Jun 10 08:15 ..\n"
                f"-rw-r--r-- 1 {p.username} {p.username}  220 Jun 10 08:15 .bash_logout\n"
                f"-rw-r--r-- 1 {p.username} {p.username} 3771 Jun 10 08:15 .bashrc\n"
                f"-rw-r--r-- 1 {p.username} {p.username} {self._rnd.randint(100,50000)} Jun 15 09:30 data.csv\n"
                f"drwxr-xr-x 2 {p.username} {p.username} 4096 Jun 15 10:23 documents\n"
                f"-rw------- 1 {p.username} {p.username} {self._rnd.randint(50,500)} Jun 15 11:02 .env")

    def _cat(self, target: str, p: DecoyPersona) -> str:
        if "passwd" in target:
            return ("root:x:0:0:root:/root:/bin/bash\n"
                    f"{p.username}:x:1000:1000:{p.username}:/home/{p.username}:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "postgres:x:114:120:PostgreSQL:/var/lib/postgresql:/bin/bash\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin")
        if "shadow" in target:
            return f"{p.username}:$6${self._rs(16)}${self._rs(86)}:19440:0:99999:7:::"
        if "hosts" in target:
            return ("127.0.0.1       localhost\n10.0.10.10      git.acme.corp\n"
                    "10.0.20.20      db-primary.internal\n10.0.30.30      cache-redis.internal")
        if target.endswith(".env"):
            return (f"DATABASE_URL=postgresql://dbuser:{self._rs(16)}@db-primary.internal:5432/app_db\n"
                    f"SECRET_KEY={self._rs(32)}\nAPI_KEY={self._rs(32)}")
        if "id_rsa" in target:
            return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(self._rs(64) for _ in range(25)) + "\n-----END RSA PRIVATE KEY-----"
        return self._rs(self._rnd.randint(50, 500))

    def _ifconfig(self, p: DecoyPersona) -> str:
        ip = self._rip()
        return (f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                f"        inet {ip}  netmask 255.255.255.0\n"
                f"        ether {self._rmac()}  txqueuelen 1000\n"
                f"        RX packets {self._rnd.randint(100000,10000000)}")

    def _find(self, args: list[str], p: DecoyPersona) -> str:
        if args and any(s in " ".join(args) for s in ["passwd", "shadow", "id_rsa", ".env"]):
            return "/etc/passwd\n/etc/shadow\n/etc/hosts\n" + f"{p.home_dir}/.ssh/id_rsa\n" + "/opt/app/.env"
        sp = args[0] if args else "."
        return f"{sp}\n{sp}/documents\n{sp}/data.csv"

    def _dl(self) -> str:
        return (f"Resolving cdn.example.com... {self._rip()}\nConnecting... connected.\n"
                f"HTTP 200 OK\nLength: {self._rnd.randint(1000,50000000)}\nSaved")

    def _hist(self) -> str:
        return "\n".join(["  1  ls -la", "  2  cd /var/www", "  3  cat config.php",
                           "  4  sudo apt update", "  5  ssh db-primary.internal",
                           "  6  ps aux", "  7  netstat -tlnp", "  8  cat /etc/passwd"])

    def _fill(self, tmpl: str, p: DecoyPersona) -> str:
        mem = self._rnd.randint(4, 128) * 1024 * 1024
        mu = int(mem * self._rnd.uniform(0.3, 0.8))
        uid = self._rnd.randint(1000, 65534)
        return tmpl.format(
            username=p.username, hostname=p.hostname, cwd=p.cwd, home=p.home_dir, shell=p.shell,
            uid=uid, gid=uid, date=datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"),
            time=datetime.now(timezone.utc).strftime("%H:%M:%S"), days=self._rnd.randint(1, 365),
            hours=self._rnd.randint(0, 23), mins=f"{self._rnd.randint(0,59):02d}", users=self._rnd.randint(1, 5),
            l1=f"{self._rnd.uniform(0.0,5.0):.2f}", l5=f"{self._rnd.uniform(0.0,5.0):.2f}", l15=f"{self._rnd.uniform(0.0,5.0):.2f}",
            mt=mem, mu=mu, mf=mem-mu, ms=int(mem*0.05), mc=int(mem*0.2), ma=mem-mu+int(mem*0.2),
            st=mem//4, sf=mem//4, bpid=self._rnd.randint(2000,9999), ppid=self._rnd.randint(2000,9999))

    def _rip(self) -> str:
        return f"{self._rnd.randint(1,223)}.{self._rnd.randint(0,255)}.{self._rnd.randint(0,255)}.{self._rnd.randint(1,254)}"

    def _rmac(self) -> str:
        return ":".join(f"{self._rnd.randint(0,255):02x}" for _ in range(6))

    def _rs(self, n: int) -> str:
        return "".join(self._rnd.choices(string.ascii_letters + string.digits + "/+=", k=n))

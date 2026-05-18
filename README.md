# EmberHoneypot

Modular AI deception and threat-intelligence platform. Lures, logs, and profiles attackers targeting AI systems.

## Architecture

```
honeypot/
├── core/          — Engine, orchestrator, emulator, attacker profiler, rate limiter
├── deception/     — Decoy personas, disinformation injector, fake data generator, response engine
├── intel/         — IoC generator, pattern matcher, threat scorer, TTP extractor
├── swarm/         — Adaptive defense, threat feed publisher, Centuria adapter
├── monitoring/    — Health checks, Prometheus metrics, structured logging, tracing
└── api/           — FastAPI server with WebSocket support
```

## Quick Start

```bash
pip install -e ".[dev]"

export HONEYPOT_API_KEY="your-secure-key-minimum-32-chars"

uvicorn honeypot.api.main:app --host 0.0.0.0 --port 8001
```

## Tests

```bash
pytest tests/ -v
```

184 tests, 0 failing.

## License

MIT

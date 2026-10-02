# EmberHoneypot

An unfinished prototype of a honeypot intended for AI services. Today it is a FastAPI management API made of placeholder endpoints over in-memory stubs, next to library code for service emulation, SQLite logging, attacker profiling and threat intel that the API does not call.

## Status

**Prototype, on hold. Not a working honeypot and not usable as a security control.** Status as of 2026-10-02.

**Do not expose this to the internet.** The API has no authentication, no rate limiting and no input limits, and there is nothing behind it that would capture an attacker.

## What works today

- The test suite passes when run as described under "Running the tests": 205 passed, 1 skipped. The tests cover the stub modules, the mock adapters and isolated library functions. None of them uses `core/service_emulator.py`, `core/interaction_logger.py`, `core/attacker_profiler.py` or `swarm/feed_publisher.py`. The skipped test records a known rate-limiter weakness and skips instead of failing.
- The FastAPI app in `api/main.py` imports and answers its 20 HTTP routes and 2 WebSocket routes when driven in-process. Honeypot instances can be created, listed and deleted as in-memory records. No port is opened for them.
- Library code that runs in isolation, called from the tests or directly:
  - `intel/ttp_extractor.py`: a regex table that maps command text to 22 MITRE ATT&CK technique IDs.
  - `intel/ioc_generator.py`, `intel/threat_scorer.py`, `intel/pattern_matcher.py`: regex IOC extraction, a fixed-weight threat score, and hand-written signature matching.
  - `deception/`: six decoy persona configs, a fake-data generator (records, credentials and a network map) and a canned shell and HTTP response engine.

## What does not work or is not implemented

- **No attacker-facing listener.** Nothing in the repo binds a port for bait traffic. Creating an instance through the API only stores a record.
- **No AI service is emulated.** There is no LLM, Ollama, OpenAI-compatible or MCP endpoint. `core/service_emulator.py` contains SSH and HTTP emulators that map input text to canned response text, with no network code, and nothing instantiates them.
- **No capture pipeline.** The app does not call the service emulator (`core/service_emulator.py`), the SQLite logger (`core/interaction_logger.py`), the full profiler (`core/attacker_profiler.py`) or the feed publisher (`swarm/feed_publisher.py`). They are library code only. The app holds the in-memory stubs in `core/logger.py` and `core/profiler.py`, and no route writes to them.
- **Management routes return fixed placeholder values.** The session, TTP, IOC, threat-score and feed routes return empty or zero results, `/api/v1/metrics` returns three fixed integers, and `/api/v1/health` returns a fixed timestamp. The swarm submit and defend routes and the tarpit and disinfo routes report `queued`, `deployed` or `injected` without doing anything.
- **No authentication** on any route, including create and delete.
- **The Sonar client** (`intel/sonar_enrichment.py`) is never called by any code outside its own tests, and those tests do not contact the API.
- **The Centuria and EmberArmor adapters are mocks.** They import no HTTP library. Pointed at an unreachable host, the Centuria adapter reports "connected" and the EmberArmor adapter reports "authenticated" for any API key. The EmberArmor adapter's safety check approves an empty request.
- **No STIX or MISP output.** The fields exist on the IOC models and nothing sets them.
- **No install.** As cloned, the package does not install or import. See below.

## Running the tests

The code imports itself as `ember_honeypot`, but the repository root is the package directory. pytest puts the clone's parent directory on the import path, so the tests run when the clone directory itself is named `ember_honeypot`. In a clone with the default directory name, pytest stops with `ModuleNotFoundError: No module named 'ember_honeypot'` and collects nothing.

These commands were run with uv 0.11.5 and Python 3.12.4 on Windows 11:

```bash
git clone https://github.com/GrandMastaShake/EmberHoneypot.git ember_honeypot
cd ember_honeypot
uv venv --python 3.12
uv pip install -e ".[dev]"
uv run --no-project python -m pytest tests/ -q
```

Result: 205 passed, 1 skipped.

Notes:

- The install step only brings in the dependencies. It installs no code from this repo.
- Use `python -m pytest`, not bare `pytest`. One test file imports `intel.sonar_enrichment` as a top-level module and needs the current directory on the import path.
- The tests make no network calls and need no API keys or environment variables.

No server command is documented here. The console script `ember-honeypot` declared in `pyproject.toml` targets `honeypot.api.main:app`, a module that does not exist, so running it fails with `ModuleNotFoundError`. The app it was meant to start is the placeholder API described above.

## Known issues

- Packaging: `pyproject.toml` names a package directory (`ember_honeypot/`) and a script module (`honeypot.api.main`) that are not in the repo.
- `core/attacker_profiler.py` and `swarm/centuria_adapter.py` end mid-statement. Both files still parse, and the affected functions raise `NameError` when called.
- `core/interaction_logger.py` raises `AttributeError` in its constructor, so the SQLite logger cannot be created. All state the app holds is in process memory.
- `require_auth` in `api/dependencies.py` is not attached to any route. `/docs` and `/openapi.json` are served.
- The API applies no input limits and never consults the rate limiter it creates. For example, `POST /api/v1/deception/fakedata` builds as many records as the caller asks for.
- `pyproject.toml` declares Python 3.11 or newer, but `intel/ttp_extractor.py` uses f-string syntax that needs 3.12.
- The response-delay coroutine in `core/orchestrator.py` and `core/engine.py` is never awaited, so the intended timing jitter does not happen. The test run prints a `RuntimeWarning` for it.
- The Sonar verdict parser in `intel/sonar_enrichment.py` returns `SAFE` when the model response is empty.
- Library code does not treat attacker text as hostile. It goes unescaped into the Sonar prompt and into generated WAF rule text, and IOC extraction also scans the decoy's own output.
- `generate_fake_files` in `deception/fake_data_generator.py` raises `TypeError`. Its `.py` template embeds the value of the `SRV_FAKE_API_KEY` environment variable in bait content, so never set that variable to a real key.
- Names from an earlier rename remain in the code: the API title is "SecureNet", and `secure_net` appears in file paths, logger names and docstrings.
- `.env.example` lists its variables without the `SRV_` prefix that `config.py` expects, so the settings class ignores them.

## Direction

The idea still stands: decoy LLM and MCP endpoints that record what automated attackers and attacking agents send. This repo is on hold while the constraint-ledger work in [EmberArmor](https://github.com/GrandMastaShake/EmberArmor) comes first. If it is picked up again, it will be rebuilt around one real listener and published field data, not extended from this scaffold.

## License

MIT. See [LICENSE](LICENSE).

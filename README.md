# Adaptive Honeypot

Python project skeleton for a localhost-only adaptive honeypot.

The initial configuration is in `config/settings.yaml`; YAML loading and
validation are provided by `config/loader.py`. SQLite schema and database
operations are in `database/`; the database starts at `data/honeypot.db` unless
another path is provided.

## Setup and tests

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m database.init_db
python -m pytest -q
```

Database operations require initialization first. To use a different database
file, pass its path to the init command:

```powershell
python -m database.init_db data\test.db
```

## Local fake services

Initialize the database, then start either service in a separate terminal:

```powershell
python -m database.init_db
python -m honeypot.tcp_service
```

```powershell
python -m honeypot.web_service
```

The TCP login service listens on `127.0.0.1:8022`; the fake web login page is
at `http://127.0.0.1:8081/login`. Both services bind only to loopback. Login
attempts record the username and password length, not the password value.
Submitted values are treated as data and are never executed.

## Local traffic simulation

Start both services in separate terminals, initialize the default database,
and run the simulator:

```powershell
python -m database.init_db
python -m honeypot.tcp_service
```

```powershell
python -m honeypot.web_service
```

```powershell
python -m simulator.runner
```

Edit `config/simulator.yaml` to change the seed, bounded scenario volumes,
and inter-request delay. The target host and ports are fixed to the project's
local services. Port discovery checks only those two known ports. SQL probes
are non-destructive strings submitted to the fake login form; directory probes
use a short fixed path list. This generator makes no requests to external
hosts and does not execute submitted input.

Ground-truth labels are written to `data/ground_truth.csv`, separate from
database event features. The CSV contains session IDs and labels; do not
include it as a model feature. The default CSV is overwritten on each run.
Run the simulator without other clients using the services so each generated
session can be labeled reliably. To choose another output path:

```powershell
python -m simulator.runner --labels data\experiment_labels.csv
```

## Numeric session features

After installing requirements, extract a pandas DataFrame from stored sessions:

```powershell
python -c "from features.extractor import extract_features; print(extract_features())"
```

The DataFrame is indexed by session ID and contains numeric columns only;
session IDs are identifiers, not feature columns. Ground-truth labels and
source IP addresses are not selected.

| Feature | Why it is useful |
|---|---|
| `event_count` | Overall activity volume within the session. |
| `tcp_connection_count` | Measures attempts to engage with the fake TCP service. |
| `http_request_count` | Measures web probing or browsing activity. |
| `login_attempt_count` | Captures repeated authentication attempts. |
| `unique_usernames` | Distinguishes broad credential guessing from repeated use of one name. |
| `unique_paths` | Captures how many different web paths were requested. |
| `session_duration_seconds` | Measures the observed span from session start through its last event. |
| `attempts_per_minute` | Normalizes login volume by duration; duration is floored at one second to avoid division by zero. |
| `payload_length_chars` | Adds up captured username/password lengths and HTTP request-path characters without storing password contents. |
| `error_count` | Counts logged protocol and HTTP error events. |
| `error_ratio` | Normalizes logged errors by event count; currently the web service does not log HTTP response status, so a 404 is not counted as an error. |
| `unique_event_types` | Describes the variety of observed interactions. |

Timestamps in the SQLite schema have one-second resolution, so very short
sessions can have a measured duration of zero seconds.

## Model training and evaluation

The default simulation config generates 10 sessions for each traffic label.
Run it once with the training seed, then again with a different seed and a
different labels file. Keep both runs in the same initialized database:

```powershell
python -m simulator.runner --labels data\train_labels.csv
```

```powershell
python -m simulator.runner --config config\simulator_evaluation.yaml --labels data\different_seed_labels.csv
```

The evaluation config has a distinct seed but matching volumes and timing.
Then train and evaluate:

```powershell
python -m ml.train --labels data\train_labels.csv --different-seed-labels data\different_seed_labels.csv
```

Training stratifies the train/test split, runs stratified cross-validation,
reports macro precision, recall, F1, one-vs-rest macro false-positive rate,
and a confusion matrix. The optional Isolation Forest baseline treats
`benign` as the inlier class and reports benign-versus-anomaly metrics. The
Random Forest artifact and JSON metrics are saved under `ml/` by default.
The separate-seed evaluation is not used for fitting or cross-validation; it
is a useful check for seed-specific pattern overfitting, not proof of
generalization to real attackers.

## Rule-based adaptations

The adaptive rules are invoked with a session ID and classifier result:

```python
from adaptive.rules import observe_classification

decision = observe_classification(session_id, "port_scan", 0.95)
```

Only the predefined labels (`benign`, `brute_force`, `port_scan`,
`sql_injection`, and `directory_probe`) and confidence values from 0 to 1 are
accepted. Classifications and resulting actions are saved to
`adaptive_actions`; sufficiently confident malicious results also create an
alert. Per-source alert thresholds move by 0.05 after a full five-result
window has at least 60% malicious or 80% benign classifications, bounded to
0.50–0.95. Three consecutive above-threshold malicious classifications enable
a 60-second rate limit. Three consecutive benign classifications clear an
active limit. A confident `port_scan` classification changes the TCP and web
service banner for that source. The services enforce persisted rate limits
with a one-second retry-after response; no traffic is redirected or sent
outside localhost.

## Streamlit dashboard

Initialize the database and launch the read-only dashboard from the project
root:

```powershell
python -m pip install -r requirements.txt
python -m database.init_db
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

The dashboard reads only from the SQLite database. It does not read simulator
labels or model artifacts. Use the sidebar to filter the date range,
classification, and alert severity. Classifications appear after they have
been recorded by the adaptive module. To view another database, set
`HONEYPOT_DB_PATH` before starting Streamlit.

## End-to-end local run

Run the complete bounded demonstration with one command. It starts the TCP
and Flask services on ephemeral loopback ports, runs the configured simulator,
classifies sessions using only stored event data, records alerts/adaptive
actions, verifies the dashboard's database queries, and starts or reuses the
Streamlit dashboard:

```powershell
python -m integration.run
```

By default this uses `config/integration.yaml`, writes labels to
`data/integration_labels.csv`, and uses `data/honeypot.db`. The dashboard is
available at `http://127.0.0.1:8501`. Use `--no-dashboard` to run the pipeline
and tests without starting the Streamlit process:

```powershell
python -m integration.run --no-dashboard
```

To check a fresh environment, create a new virtual environment, install the
declared dependencies, initialize a database, run all tests, and exercise the
complete local pipeline:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\clean_install_check.ps1
```

The check uses a temporary virtual environment and SQLite files, then removes
them when it finishes.

## Install, configure, run, and test

This run used Python 3.14.5; other Python versions have not been verified in
this environment. From PowerShell in the project directory, create and
activate an isolated environment, install the dependency ranges, and initialize
the local database:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m database.init_db
```

If PowerShell blocks activation, either allow it for the current terminal with
`Set-ExecutionPolicy -Scope Process Bypass`, or call
`.venv\Scripts\python.exe` instead of activating the environment.

The simulator reads `config/simulator.yaml`,
`config/simulator_evaluation.yaml`, and `config/integration.yaml` for seed,
scenario counts, and delay. `config/settings.yaml` has a standalone validator
covered by tests, but the service entry points do not load it; they use fixed
loopback hosts and their documented default ports. These files contain no
credentials. `.env.example` is only a placeholder: the application does not
load `.env` and requires no secrets. The dashboard reads `HONEYPOT_DB_PATH`
from the process environment; otherwise it uses `data/honeypot.db`. To select
another database in PowerShell:

```powershell
$env:HONEYPOT_DB_PATH = "data\alternate.db"
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

The exact commands for the services, simulator, model, adaptive rules,
dashboard, and full pipeline are in the sections above. The full automated test
suite and coverage report can be run with:

```powershell
python -m coverage run --source=config,database,honeypot,simulator,features,ml,adaptive,dashboard,integration -m pytest -q
python -m coverage report -m
```

The clean-install script uses a temporary virtual environment, installs
`requirements.txt`, initializes a temporary database, runs pytest, and then
runs the full localhost pipeline against a separate temporary database. It
uses `--no-dashboard` to avoid starting a second Streamlit process; the
pipeline still checks the dashboard's database queries:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\clean_install_check.ps1
```

## Troubleshooting

| Symptom | Check |
|---|---|
| `Address already in use` | Stop the existing process using TCP 8022, web 8081, or dashboard 8501, or use `python -m integration.run --no-dashboard` for the integrated services on ephemeral ports. |
| Empty dashboard | Initialize the selected SQLite database and run the simulator or `python -m integration.run`; confirm `HONEYPOT_DB_PATH` points to the same file. |
| No classification in dashboard | The dashboard reads recorded database classifications, not ground-truth CSV labels. Run the integration pipeline to create classifications and alerts. |
| Missing or malformed YAML | Check the named YAML file and required keys; the config loader raises `ConfigError` with the missing/invalid setting. |
| `.env` changes have no effect | `.env` is not read by this project. Set `HONEYPOT_DB_PATH` in the same PowerShell process that launches Streamlit. |
| Invalid port or input | Service ports are validated before binding. TCP lines are limited to 512 bytes and UTF-8 decoding errors are logged as protocol errors; the web app limits request bodies to 16 KiB. |
| Database or schema error | Run `python -m database.init_db` for the selected database and retain the exception/log output. SQLite failures are logged and re-raised or returned as service-unavailable responses. |
| Tests fail after a local run | Run `python -m pytest -q` from the project root and include the first failure traceback when investigating. Tests use temporary databases and do not depend on the checked-in demo database. |

## Observed limitations

- The simulator creates synthetic, bounded examples of five traffic classes.
  Its output is not representative of the diversity or behavior of real
  attackers: the credential, SQL-probe, and directory-path vocabularies are
  short fixed lists, and the port scan checks only the known local service
  ports.
- Both fake services are deliberately restricted to `127.0.0.1`; this is a
  local educational demonstration, not a remotely deployable honeypot.
- The fake login services always reject credentials and store password length
  rather than password contents; they do not model successful authentication.
- The end-to-end integration runner classifies recorded event patterns with a
  deterministic heuristic. It records adaptive actions but does not load or
  invoke the trained Random Forest model.
- The standalone `config/settings.yaml` loader is validated by tests but is
  not wired into the service launchers; service binding and default ports are
  defined by the service modules. `.env` files are not loaded.
- The saved Random Forest is trained and evaluated on small simulator datasets.
  A different simulator seed tests sensitivity to generated variation only; it
  is not an independent real-world validation.
- SQLite event timestamps have one-second text resolution, so sub-second
  session duration is not represented precisely.
- The recorded evaluation was run on Python 3.14.5; other interpreter versions
  were not tested in this environment.
- The TCP service handles one username/password line pair per connection;
  line length and web request body size are bounded, and the Flask development
  server is used for the local web service.

## Report and screenshot evidence

The generated `report_answers.txt` records the measured dataset, feature,
evaluation, adaptive, test, database/dashboard, and robustness results, along
with explicit notes where a requested quantity was not measured. The
`screenshots/` directory contains the project tree, schema, service and
simulator evidence, model/report plots, adaptation and validation evidence,
and dashboard views. The screenshot directory README describes which images
are browser captures and which are rendered from actual run output or source.

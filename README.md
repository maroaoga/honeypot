# Adaptive Honeypot

Python project skeleton for a localhost-only adaptive honeypot.

The configuration is in `config/settings.yaml`; YAML loading and validation
are provided by `config/loader.py`. Optional local values are loaded from
`.env` using the standard library, with already-exported environment variables
taking precedence. SQLite starts at `data/honeypot.db` unless overridden.

## Setup and tests

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m database.init_db
python -m pytest -q
```

Scikit-learn is pinned to 1.9.0 to match the saved joblib model artifacts;
retrain and resave the model if you change this version.

Database operations require initialization first. To use a different database
file, pass its path to the init command:

```powershell
python -m database.init_db data\test.db
```

## Local fake services

Initialize the database, then start either service in a separate terminal:

```powershell
python -m database.init_db
python -m honeypot.tcp_service --config config\settings.yaml
```

```powershell
python -m honeypot.web_service --config config\settings.yaml
```

Both launchers accept `--config`; the validated YAML selects distinct TCP
and web ports and enforces the `127.0.0.1` bind address. Defaults are
`127.0.0.1:8022` and `127.0.0.1:8081`. The TCP service supports up to 50
attempts per connection. Login attempts record usernames and password lengths,
not password values. Submitted values are treated as data and never executed.
Copy `.env.example` to `.env` for optional local overrides:
`HONEYPOT_DB_PATH`, `HONEYPOT_CONFIG_PATH`, `HONEYPOT_TCP_PORT`, and
`HONEYPOT_WEB_PORT`. The YAML host cannot be overridden away from loopback.

## Local traffic simulation

Start both services in separate terminals, initialize the default database,
and run the simulator:

```powershell
python -m database.init_db
python -m honeypot.tcp_service --config config\settings.yaml
```

```powershell
python -m honeypot.web_service --config config\settings.yaml
```

```powershell
python -m simulator.runner
```

The default config generates 300 labeled sessions per class (1,500 total).
Each brute-force session uses one TCP connection containing 5–50 login
attempts, with varied usernames. Benign sessions include typo-like names and
long dummy inputs. Twenty percent of attack sessions receive configured
50–100 ms delays; brute-force attempts in those sessions are paced as well.
The simulator binds client sockets to `127.0.0.1`, `.2`, or `.3`; both servers
remain bound only to `127.0.0.1`. These are loopback aliases on this machine,
not remote hosts. SQL probes are inert strings sent only to the fake login
form; directory probes use a short fixed path list.

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
| `source_attempts_60s` | Counts login attempts from the same source IP in the 60 seconds ending at this session's last event. |
| `source_distinct_usernames_60s` | Counts distinct usernames from that source in the same trailing window. |
| `source_request_rate_per_second_60s` | Counts TCP connections and HTTP requests from that source in the window, divided by 60 seconds. |

Source IPs are used only to group rolling-window events and are not emitted as
features. Labels are not read by the extractor. New databases store timestamps
to millisecond resolution; rolling features include events at or before the
current session's final event and exclude later events.

## Model training and evaluation

Run the reproducible full experiment to create isolated 300-per-class training
and different-seed datasets, train the model, save evaluation files, and run
the model-backed integration flow:

```powershell
python -m scripts.run_experiment
```

The script writes ground-truth CSVs, config snapshots, features, per-class
feature means, cross-validation scores, Random Forest feature importances,
confusion matrix CSV/plot, metrics, and the saved model under `results/`.
Training uses a stratified 75/25 split and 5-fold stratified cross-validation.
It reports per-class and macro precision, recall, F1, one-vs-rest false
positive rate, training/prediction time, Logistic Regression and optional
Isolation Forest baselines. The different-seed dataset is stored in a separate
database and is used only for evaluation, not fitting or cross-validation.

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

After training, run the bounded demonstration. It starts TCP and Flask services
on ephemeral loopback ports, runs the integration simulator, loads the saved
Random Forest, classifies extracted database features, records alerts/adaptive
actions, verifies dashboard queries, and can launch Streamlit:

```powershell
python -m integration.run
```

By default this uses `config/integration.yaml`, writes labels to
`data/integration_labels.csv`, and uses `data/honeypot.db`. It expects the
trained model at `results/random_forest.joblib`. The dashboard is
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

The simulator reads the YAML configs for seed, source IPs, class volumes,
attempt counts, and timing. Both service entry points load the validated
`config/settings.yaml`; `.env` values are loaded at process startup and exported
environment variables override them. No credentials or secrets are required.
The dashboard reads `HONEYPOT_DB_PATH`, otherwise `data/honeypot.db`. To select
another database in PowerShell:

```powershell
$env:HONEYPOT_DB_PATH = "data\alternate.db"
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

The exact commands for the services, simulator, model, adaptive rules,
dashboard, and full pipeline are in the sections above. The full automated test
suite and coverage report can be run with:

```powershell
python -m coverage run --source=config,database,honeypot,simulator,features,ml,adaptive,dashboard,integration,scripts -m pytest -q
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
| `.env` changes have no effect | `.env` is loaded at process startup; verify the file is in the project root and that an exported environment value is not overriding it. |
| Invalid port or input | Service ports are validated before binding. TCP lines are limited to 512 bytes and UTF-8 decoding errors are logged as protocol errors; the web app limits request bodies to 16 KiB. |
| Database or schema error | Run `python -m database.init_db` for the selected database and retain the exception/log output. SQLite failures are logged and re-raised or returned as service-unavailable responses. |
| Tests fail after a local run | Run `python -m pytest -q` from the project root and include the first failure traceback when investigating. Tests use temporary databases and do not depend on the checked-in demo database. |

## Observed limitations

- The simulator creates synthetic, bounded examples of five traffic classes.
  Its output is not representative of the diversity or behavior of real
  attackers: the credential, SQL-probe, and directory-path vocabularies remain
  short fixed lists, and port-scan probes touch only the known fake services.
  Low-and-slow delays and typo/long benign input are synthetic, configured
  patterns, not measured human or adversary behavior.
- Both fake services are deliberately restricted to `127.0.0.1`; this is a
  local educational demonstration, not a remotely deployable honeypot.
- The fake login services always reject credentials and store password length
  rather than password contents; they do not model successful authentication.
- Simulator source addresses are three loopback aliases on one machine; they
  do not represent independent hosts or network paths.
- The Random Forest is trained and evaluated only on synthetic data. A
  different simulator seed tests sensitivity to generated variation, not
  generalization to real attackers.
- Source-window features can be affected by the artificial sequencing and
  source assignment in the simulator. The window uses observed database
  timestamps and does not model packet-level timing.
- SQLite event timestamps in new databases have millisecond resolution, not
  packet-level or microsecond precision.
- The recorded evaluation was run on Python 3.14.5; other interpreter versions
  were not tested in this environment.
- The TCP service handles one username/password line pair per connection;
  line length and web request body size are bounded, and the Flask development
  server is used for the local web service.

## Report and screenshot evidence

The generated `report_answers.txt` records measured dataset, feature,
evaluation, adaptive, test, database/dashboard, and robustness results. The
latest expanded 300-per-class results are saved in `results/` and summarized
in the report. The
`screenshots/` directory contains the project tree, schema, service and
simulator evidence, model/report plots, adaptation and validation evidence,
and dashboard views. The screenshot directory README describes which images
are browser captures and which are rendered from actual run output or source.

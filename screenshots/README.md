# Evidence screenshots

These images are generated from the checked-in project files, SQLite database,
simulation labels, model metrics, and test/service runs. `dashboard_overview`,
`dashboard_filtered_events`, `dashboard_events_table`, `dashboard_empty`, and
`fake_web_login` are captured from the running local web apps. Other evidence
images are rendered from actual outputs and source files; they are not
photographs of a VS Code window, DB Browser, or terminal.

Evidence index:

- `project_structure.png` - generated project tree.
- `database_schema.png` - schema.sql, SQLite table columns, and row totals.
- `services_localhost.png`, `service_logging_rows.png` - service bind and
  20-connection test evidence.
- `fake_web_login.png` - actual fake login page in Edge.
- `simulator_run.png` - isolated end-to-end simulator output.
- `features_head.png`, `feature_class_means.png` - feature DataFrame and class
  summary.
- `model_training_metrics.png`, `evaluation_metrics.png`,
  `confusion_matrix.png`, `feature_importance.png`, `cv_different_seed.png` -
  real training and evaluation results.
- `adaptive_action_rows.png`, `adaptive_scenarios.png` - persisted actions and
  before/after scenarios.
- `code_logging_function.png`, `code_feature_extractor.png`,
  `code_classifier_call.png`, `code_random_forest.png`,
  `code_adaptive_rule.png`,
  `secure_coding_evidence.png` - source excerpts and validation evidence.
- `pytest_coverage.png`, `robustness_checks.png` - real test summary and
  observed error handling.
- `clean_install_check.png` - fresh virtual-environment install, test, and
  pipeline run output.
- `dashboard_overview.png`, `dashboard_filtered_events.png`,
  `dashboard_events_table.png`, `dashboard_empty.png` - actual Streamlit
  dashboard views.
- `dashboard_sql_comparison.png` - direct SQL and dashboard values.

The project-tree image reflects the files present when it was generated. The
dashboard and database images reflect the local demo database and may differ
after another run. VS Code and DB Browser screenshots could not be captured in
this environment; the tree and schema images are generated representations.

"""
Brand Guard evaluation tooling (plan Stage 1): corpus construction, gold-set
handling and — in later steps — the offline replay harness and metrics.

Deliberately separate from `app/`: nothing here ships with the API, and it must
not import detector logic for *labelling* (labels and strata use the literal
rules in `domains.py`, so the harness doesn't grade the detector with its own
confusable tables).
"""

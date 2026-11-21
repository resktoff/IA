PY ?= python3

.PHONY: help test selfcheck demo web verify clean

help:
	@echo "make test       - suite completa de tests (stdlib unittest, sin dependencias)"
	@echo "make selfcheck  - ejercita los controles y el pipeline; escribe evidence/selfcheck.md"
	@echo "make demo       - evaluación local con examples/scope-local.json -> evidence/"
	@echo "make web        - inicia la interfaz web solo en 127.0.0.1:8765"
	@echo "make verify     - test + selfcheck + verificación de la cadena de auditoría"
	@echo "make clean      - borra evidence/ y __pycache__"

test:
	$(PY) -m unittest discover -s tests -t . -v

selfcheck:
	$(PY) -m sentinel.cli self-check --out evidence

demo:
	$(PY) -m sentinel.cli assess --scope examples/scope-local.json --mode local --out evidence

web:
	$(PY) -m sentinel.webapp --port 8765

verify: test selfcheck demo
	@for f in evidence/audit-*.jsonl; do $(PY) -m sentinel.cli verify-audit "$$f" >/dev/null && echo "audit OK: $$f"; done

clean:
	rm -rf evidence
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

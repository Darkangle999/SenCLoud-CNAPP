# Odineyes — Makefile
# Works on Arch Linux, Ubuntu, macOS — never touches system Python

VENV    := .venv
PY      := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
CS      := $(VENV)/bin/odineyes

.PHONY: help venv install install-core install-aws install-azure install-gcp \
        dev scan scan-all scan-ci list compliance report risk inventory clean test lint

help:
	@echo ""
	@echo "  ╔══════════════════════════════════════════════╗"
	@echo "  ║  CloudSentinel v2.0 — Make Targets           ║"
	@echo "  ╚══════════════════════════════════════════════╝"
	@echo ""
	@echo "  Setup:"
	@echo "    make install        Full install (AWS + Azure + GCP SDKs)"
	@echo "    make install-core   Core only — no cloud SDKs (fastest)"
	@echo "    make install-aws    Core + AWS boto3"
	@echo "    make install-azure  Core + Azure SDK"
	@echo "    make install-gcp    Core + GCP SDK"
	@echo "    make dev            Full install + dev tools (pytest, ruff, black)"
	@echo ""
	@echo "  Scanning:"
	@echo "    make scan           Demo AWS scan → HTML report"
	@echo "    make scan-all       All providers, all compliance frameworks"
	@echo "    make scan-ci        CI/CD mode (fail-on critical, JSON output)"
	@echo "    make list           List all available checks"
	@echo "    make compliance     Show CIS compliance mapping"
	@echo "    make risk           Risk score analysis"
	@echo "    make inventory      Enumerate cloud resources"
	@echo ""
	@echo "  Dev:"
	@echo "    make test           Run test suite"
	@echo "    make lint           Run ruff + black"
	@echo "    make clean          Remove venv and build artifacts"
	@echo ""

# ── Virtual environment ───────────────────────────────────────

venv:
	@echo "→ Creating venv..."
	@rm -rf src/odineyes.egg-info 2>/dev/null || true
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip --quiet
	@echo "✓ $(VENV)/ ready"

# ── Install targets ───────────────────────────────────────────

install-core: venv
	@echo "→ Installing core deps + Odineyes..."
	$(PIP) install -e "." --quiet
	@echo "✅ Core install done"
	@echo "   $(CS) --help"

install-aws: venv
	@echo "→ Installing core + AWS SDK..."
	$(PIP) install -e ".[aws]" --quiet
	@echo "✅ AWS install done"

install-azure: venv
	@echo "→ Installing core + Azure SDK..."
	$(PIP) install -e ".[azure]" --quiet
	@echo "✅ Azure install done"

install-gcp: venv
	@echo "→ Installing core + GCP SDK..."
	$(PIP) install -e ".[gcp]" --quiet
	@echo "✅ GCP install done"

install: venv
	@echo "→ Installing all cloud SDKs (boto3, azure, gcp)..."
	$(PIP) install -e ".[all]" --quiet
	@echo "✅ Full install done — run: make scan"

dev: venv
	@echo "→ Installing full dev environment..."
	$(PIP) install -e ".[all]" --quiet
	$(PIP) install pytest pytest-cov black ruff mypy --quiet
	@echo "✅ Dev environment ready"

# ── Run commands ──────────────────────────────────────────────

scan:
	$(CS) scan --provider aws --compliance CIS --compliance SOC2 \
	  --format html --output ./cloudsentinel-report

scan-all:
	$(CS) scan --all-providers \
	  --compliance CIS --compliance SOC2 --compliance HIPAA \
	  --format all --output ./cloudsentinel-report

scan-ci:
	$(CS) scan --provider aws --compliance CIS \
	  --fail-on critical --quiet \
	  --format json --output ./ci-results

list:
	$(CS) list-checks

list-aws:
	$(CS) list-checks --provider aws

list-critical:
	$(CS) list-checks --severity critical

compliance:
	$(CS) compliance --framework CIS --provider aws

compliance-all:
	@for fw in CIS SOC2 HIPAA PCI-DSS NIST ISO27001 GDPR FedRAMP; do \
		echo ""; \
		$(CS) compliance --framework $$fw --provider aws; \
	done

risk:
	@[ -f cloudsentinel-report.json ] && \
	  $(CS) risk-score --input cloudsentinel-report.json || \
	  echo "Run 'make scan' first to generate results."

inventory:
	$(CS) inventory --provider aws

# ── Dev ───────────────────────────────────────────────────────

test:
	$(PY) -m pytest src/odineyes/tests/ -v

test-quick:
	$(PY) -m unittest src/odineyes/tests/test_cloudsentinel.py -v

lint:
	$(VENV)/bin/ruff check src/ --fix
	$(VENV)/bin/black src/

# ── Cleanup ───────────────────────────────────────────────────

clean:
	rm -rf $(VENV) *.egg-info src/*.egg-info dist build .pytest_cache
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Cleaned"

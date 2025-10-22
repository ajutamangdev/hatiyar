.PHONY: help shell check serve format lint test clean install

# Default target - show help
.DEFAULT_GOAL := help

# Python interpreter
PYTHON := python3

# Source directory
SRC_DIR := src/pysecfw

# Virtual environment directory
VENV_DIR := .venv

##@ General

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

shell: ## Launch the interactive pysecfw shell
	$(PYTHON) $(SRC_DIR)/main.py shell

serve: ## Audit using the web interface
	$(PYTHON) $(SRC_DIR)/main.py serve

install: ## Install dependencies using uv
	uv sync

##@ Code Quality

check: lint type-check ## Run all checks (linting + type checking)

lint: ## Run ruff linter
	uvx ruff check .

type-check: ## Run mypy type checker
	mypy .

format: ## Format code with ruff
	uvx ruff format .

fix: ## Auto-fix linting issues
	uvx ruff check --fix .

##@ Cleanup

clean: ## Remove build artifacts and cache files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -r dist/ build/ 2>/dev/null || true

##@ Information

info: ## Display project information
	@echo "pysecfw - Python Security Framework"
	@echo "======================================"
	@echo "Python version: $(shell $(PYTHON) --version)"
	@echo "UV version: $(shell uvx --version 2>/dev/null || echo 'not installed')"
	@echo "Mypy version: $(shell mypy --version 2>/dev/null || echo 'not installed')"
	@echo "Ruff version: $(shell uvx ruff --version 2>/dev/null || echo 'not installed')"
	@echo ""
	@echo "Source directory: $(SRC_DIR)"
	@echo "Virtual environment: $(VENV_DIR)"

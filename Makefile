# Makefile for K8s AI Log Analyzer

.PHONY: help install install-dev test lint format clean build run-example setup

# Default target
help:
	@echo "Available targets:"
	@echo "  help         - Show this help message"
	@echo "  setup        - Set up development environment"
	@echo "  install      - Install the package"
	@echo "  install-dev  - Install with development dependencies"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linting checks"
	@echo "  format       - Format code with black and isort"
	@echo "  clean        - Clean build artifacts"
	@echo "  build        - Build distribution packages"
	@echo "  init-config  - Initialize configuration"
	@echo "  run-test     - Test connections"
	@echo "  run-health   - Check cluster health"
	@echo "  run-analyze  - Run single analysis"

# Set up development environment
setup:
	python -m venv venv
	@echo "Virtual environment created. Activate with:"
	@echo "  Windows: venv\\Scripts\\activate"
	@echo "  Unix/Mac: source venv/bin/activate"
	@echo "Then run: make install-dev"

# Install the package
install:
	pip install -e .

# Install with development dependencies
install-dev:
	pip install -e .[dev]

# Run tests
test:
	python -m pytest tests/ -v

# Run linting
lint:
	python -m mypy k8sai/
	python -m black --check k8sai/ tests/
	python -m isort --check-only k8sai/ tests/

# Format code
format:
	python -m black k8sai/ tests/
	python -m isort k8sai/ tests/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

# Build distribution packages
build: clean
	python setup.py sdist bdist_wheel

# Initialize configuration
init-config:
	python -m k8sai.main init-config

# Test connections
run-test:
	python -m k8sai.main test

# Check cluster health
run-health:
	python -m k8sai.main health

# Run single analysis
run-analyze:
	python -m k8sai.main analyze

# Quick analysis
run-quick:
	python -m k8sai.main quick --hours 1
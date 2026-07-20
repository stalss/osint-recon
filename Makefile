.PHONY: install install-dev build build-all clean test uninstall

install:
	pip install .

install-dev:
	pip install -e ".[dev]"

build:
	pip install pyinstaller
	pyinstaller --onefile --name osint-recon --clean osint_recon/cli.py

build-linux:
	pip install pyinstaller
	pyinstaller --onefile --name osint-recon --clean osint_recon/cli.py
	@echo "Binary: dist/osint-recon"

build-macos:
	pip install pyinstaller
	pyinstaller --onefile --name osint-recon --clean osint_recon/cli.py
	@echo "Binary: dist/osint-recon"

build-windows:
	pip install pyinstaller
	pyinstaller --onefile --name osint-recon.exe --clean osint_recon/cli.py
	@echo "Binary: dist/osint-recon.exe"

build-all: build-linux build-macos build-windows

test:
	python -m pytest tests/ -v

clean:
	rm -rf build/ dist/ *.spec __pycache__ osint_recon/__pycache__ osint_recon/modules/__pycache__

uninstall:
	pip uninstall osint-recon -y

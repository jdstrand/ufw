#    Copyright 2008-2024 Canonical Ltd.
#    Copyright 2025 Jamie Strandboge
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.

PYTHON ?= python3
DESTDIR ?=
PREFIX ?= /usr
SYSCONFDIR ?= /etc
LIBDIR ?= /lib
DATADIR ?= $(PREFIX)/share

STAGE_DIR = build/stage
TMPDIR = ./tmp

# Find iptables location
IPTABLES_DIR ?= $(shell for dir in /usr/sbin /sbin /usr/bin /bin /usr/local/sbin /usr/local/bin; do \
	if [ -x $$dir/iptables ]; then echo $$dir; break; fi; done)

# Get version from setup.cfg
VERSION := $(shell grep '^version = ' setup.cfg | cut -d' ' -f3)

# Files that need path substitution during 'build' target
CONF_RULES = before.rules after.rules before6.rules after6.rules user.rules user6.rules
CONF_FILES = ufw.conf sysctl.conf ufw.defaults
INIT_FILES = ufw-init ufw-init-functions before.init after.init

# Translation files
SRCS = $(wildcard src/*.py)
POTFILES = locales/po/ufw.pot

# Tarball variables
# Use --exclude-vcs to exclude .git and --exclude-vcs-ignores to honor .gitignore
# Add additional patterns not in .gitignore
EXCLUDES = --exclude-vcs --exclude-vcs-ignores --exclude='*~' --exclude='.github' --exclude='debian' --exclude='ubuntu' --exclude=AGENTS.md
SRCVER = ufw-$(VERSION)
TARBALLS = ../tarballs
TARSRC = $(TARBALLS)/$(SRCVER)
TARDST = $(TARBALLS)/$(SRCVER).tar.gz

# Syntax check variables
PYFLAKES = $(TMPDIR)/pyflakes.out
ifeq ($(PYTHON),python3)
PYFLAKES_EXE = pyflakes3
else
PYFLAKES_EXE = pyflakes
endif

.PHONY: all build install clean translations mo test unittest coverage coverage-report man-check check syntax-check tarball

all: build

build:
	@echo "Building UFW $(VERSION)..."
	@echo "Found iptables in: $(IPTABLES_DIR)"

	# Clean and create staging directory
	rm -rf $(STAGE_DIR)
	mkdir -p $(STAGE_DIR)/src $(STAGE_DIR)/conf $(STAGE_DIR)/doc $(STAGE_DIR)/profiles

	@echo "Copying install files to $(STAGE_DIR)..."
	cp src/*.py src/*.init src/ufw-init src/ufw-init-functions $(STAGE_DIR)/src/
	cp conf/* $(STAGE_DIR)/conf/
	cp doc/*.8 $(STAGE_DIR)/doc/
	cp profiles/* $(STAGE_DIR)/profiles/
	@if [ -d locales/mo ]; then \
		mkdir -p $(STAGE_DIR)/locales; \
		cp -r locales/mo $(STAGE_DIR)/locales/; \
	fi

	@echo "Updating paths in Python sources..."
	sed -i 's|#CONFIG_PREFIX#|$(SYSCONFDIR)|g' $(STAGE_DIR)/src/common.py
	sed -i 's|#STATE_PREFIX#|$(LIBDIR)/ufw|g' $(STAGE_DIR)/src/common.py
	sed -i 's|#PREFIX#|$(PREFIX)|g' $(STAGE_DIR)/src/common.py
	sed -i 's|#IPTABLES_DIR#|$(IPTABLES_DIR)|g' $(STAGE_DIR)/src/common.py
	sed -i 's|#SHARE_DIR#|$(DATADIR)/ufw|g' $(STAGE_DIR)/src/common.py
	@if [ -n "$$UFW_SKIP_CHECKS" ]; then \
		echo "Updating do_checks"; \
		sed -i 's|do_checks = True|do_checks = False|g' $(STAGE_DIR)/src/common.py; \
	fi

	# Update main.py
	@echo "Updating version and interpreter in main.py..."
	sed -i 's|#VERSION#|$(VERSION)|g' $(STAGE_DIR)/src/main.py
	sed -i '1s|^#.*python.*|#!/usr/bin/env $(PYTHON)|' $(STAGE_DIR)/src/main.py

	# Modify system configuration files in staging
	@echo "Updating paths in configuration files..."
	@for f in $(CONF_RULES); do \
		sed -i \
			-e 's|#CONFIG_PREFIX#|$(SYSCONFDIR)|g' \
			-e 's|#PREFIX#|$(PREFIX)|g' \
			-e 's|#STATE_PREFIX#|$(LIBDIR)/ufw|g' \
			-e 's|#VERSION#|$(VERSION)|g' \
			$(STAGE_DIR)/conf/$$f; \
	done
	@for f in $(CONF_FILES); do \
		sed -i \
			-e 's|#CONFIG_PREFIX#|$(SYSCONFDIR)|g' \
			-e 's|#PREFIX#|$(PREFIX)|g' \
			-e 's|#STATE_PREFIX#|$(LIBDIR)/ufw|g' \
			-e 's|#VERSION#|$(VERSION)|g' \
			$(STAGE_DIR)/conf/$$f; \
	done
	@for f in $(INIT_FILES); do \
		sed -i \
			-e 's|#CONFIG_PREFIX#|$(SYSCONFDIR)|g' \
			-e 's|#PREFIX#|$(PREFIX)|g' \
			-e 's|#STATE_PREFIX#|$(LIBDIR)/ufw|g' \
			-e 's|#VERSION#|$(VERSION)|g' \
			$(STAGE_DIR)/src/$$f; \
	done

	@echo "Updating paths in man pages..."
	sed -i 's|#CONFIG_PREFIX#|$(SYSCONFDIR)|g' $(STAGE_DIR)/doc/*.8
	sed -i 's|#PREFIX#|$(PREFIX)|g' $(STAGE_DIR)/doc/*.8
	sed -i 's|#STATE_PREFIX#|$(LIBDIR)/ufw|g' $(STAGE_DIR)/doc/*.8
	sed -i 's|#VERSION#|$(VERSION)|g' $(STAGE_DIR)/doc/*.8

	@echo "Build complete in $(STAGE_DIR)"

install: build
	@echo "Installing UFW to $(DESTDIR)$(PREFIX)..."

	# Install Python modules
	install -d $(DESTDIR)$(PREFIX)/lib/python3/dist-packages/ufw
	install -m 644 $(STAGE_DIR)/src/*.py $(DESTDIR)$(PREFIX)/lib/python3/dist-packages/ufw/

	# Install the ufw command script
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 $(STAGE_DIR)/src/main.py $(DESTDIR)$(PREFIX)/sbin/ufw

	# Install manpages
	install -d $(DESTDIR)$(DATADIR)/man/man8
	install -m 644 $(STAGE_DIR)/doc/ufw.8 $(DESTDIR)$(DATADIR)/man/man8/
	install -m 644 $(STAGE_DIR)/doc/ufw-framework.8 $(DESTDIR)$(DATADIR)/man/man8/

	# Install state files and helper scripts
	install -d $(DESTDIR)$(LIBDIR)/ufw
	install -m 755 $(STAGE_DIR)/src/ufw-init $(DESTDIR)$(LIBDIR)/ufw/
	install -m 755 $(STAGE_DIR)/src/ufw-init-functions $(DESTDIR)$(LIBDIR)/ufw/

	# Install configuration files
	install -d $(DESTDIR)$(SYSCONFDIR)/default
	install -m 644 $(STAGE_DIR)/conf/ufw.defaults $(DESTDIR)$(SYSCONFDIR)/default/ufw

	install -d $(DESTDIR)$(SYSCONFDIR)/ufw
	install -m 644 $(STAGE_DIR)/conf/ufw.conf $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 644 $(STAGE_DIR)/conf/sysctl.conf $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/conf/before.rules $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/conf/after.rules $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/conf/before6.rules $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/conf/after6.rules $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/conf/user.rules $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/conf/user6.rules $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/src/before.init $(DESTDIR)$(SYSCONFDIR)/ufw/
	install -m 640 $(STAGE_DIR)/src/after.init $(DESTDIR)$(SYSCONFDIR)/ufw/

	# Install application profiles
	install -d $(DESTDIR)$(SYSCONFDIR)/ufw/applications.d
	install -m 644 $(STAGE_DIR)/profiles/* $(DESTDIR)$(SYSCONFDIR)/ufw/applications.d/

	# Install pristine copies of rules files
	install -d $(DESTDIR)$(DATADIR)/ufw/iptables
	install -m 644 $(STAGE_DIR)/conf/before.rules $(DESTDIR)$(DATADIR)/ufw/iptables/
	install -m 644 $(STAGE_DIR)/conf/after.rules $(DESTDIR)$(DATADIR)/ufw/iptables/
	install -m 644 $(STAGE_DIR)/conf/before6.rules $(DESTDIR)$(DATADIR)/ufw/iptables/
	install -m 644 $(STAGE_DIR)/conf/after6.rules $(DESTDIR)$(DATADIR)/ufw/iptables/
	install -m 644 $(STAGE_DIR)/conf/user.rules $(DESTDIR)$(DATADIR)/ufw/iptables/
	install -m 644 $(STAGE_DIR)/conf/user6.rules $(DESTDIR)$(DATADIR)/ufw/iptables/

	# Install translations if they exist
	@if [ -d "$(STAGE_DIR)/locales/mo" ] && [ -n "$$(ls -A $(STAGE_DIR)/locales/mo 2>/dev/null)" ]; then \
		echo "Installing translations..."; \
		install -d $(DESTDIR)$(DATADIR)/ufw/messages; \
		cp -r $(STAGE_DIR)/locales/mo/* $(DESTDIR)$(DATADIR)/ufw/messages/ 2>/dev/null || true; \
	fi

	@echo "Installation complete"

translations: $(POTFILES)
$(POTFILES): $(SRCS)
	xgettext -d ufw -L Python -o $@ $(SRCS)

mo:
	make -C locales all

test:
	./run_tests.sh -s -i $(PYTHON)

unittest:
	./run_tests.sh -s -i $(PYTHON) unit

coverage:
	$(PYTHON) -m coverage run ./tests/unit/runner.py

coverage-report:
	$(PYTHON) -m coverage report --show-missing --omit="tests/*"

man-check:
	$(shell mkdir -p $(TMPDIR) 2>/dev/null)
	@for manfile in doc/*.8; do \
		page=$$(basename $$manfile); \
		manout=$(TMPDIR)/$$page.out; \
		echo "Checking $$page for errors... "; \
		PAGER=cat LANG='en_US.UTF-8' MANWIDTH=80 man --warnings -E UTF-8 -l $$manfile >/dev/null 2> "$$manout"; \
		cat "$$manout"; \
		test ! -s "$$manout" || exit 1; \
		echo "PASS"; \
	done

check: man-check test unittest

syntax-check: clean
	./tests/run-flake8
	./tests/run-pylint

style-check: clean
	./tests/run-black

style-fix: clean
	black ./src/*.py ./tests/*/*.py

# require language-checker to be installed in CI but not one local system
inclusivity-check: clean
	@echo "\n# Check for non-inclusive language"; \
	if test -n "$(CI)" ; then \
		language-checker --exit-1-on-failure . ; \
	elif which language-checker >/dev/null ; then \
		language-checker --exit-1-on-failure . ; \
	else \
		echo "Could not find language-checker!" ; \
	fi \

tarball: style-check inclusivity-check syntax-check clean translations
	@echo "Creating tarball for version $(VERSION)..."
	mkdir -p $(TARBALLS)
	cp -a . $(TARSRC)
	tar -zcv -C $(TARBALLS) $(EXCLUDES) -f $(TARDST) $(SRCVER)
	rm -rf $(TARSRC)
	@echo "Tarball created: $(TARDST)"

clean:
	rm -rf $(STAGE_DIR)
	rm -rf build
	rm -rf $(TMPDIR)
	rm -rf *.egg-info*
	rm -rf src/__pycache__ tests/__pycache__
	rm -rf tests/unit/__pycache__ tests/functional/__pycache__
	rm -f src/*.pyc tests/*.pyc tests/unit/*.pyc tests/functional/*.pyc
	rm -f locales/mo/*.mo
	rm -f .coverage

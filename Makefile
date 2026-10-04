# Developer shortcuts. Everything here is optional; the extensions need no build step.
EXT ?= samba-adc
VERSION := $(shell cat $(EXT)/VERSION 2>/dev/null)

.PHONY: help lint test check dist install uninstall clean
help:
	@echo "make lint       shellcheck + syntax checks"
	@echo "make test       unit tests (needs: cd $(EXT) && npm ci)"
	@echo "make check      package consistency (manifest, installer list, versions, changelog)"
	@echo "make dist       build dist/$(EXT)-<version>.tar.gz"
	@echo "make install    sudo ./install.sh $(EXT)"
	@echo "Choose another extension with EXT=<dir>."

lint:
	shellcheck -x $$(git ls-files '*.sh' 2>/dev/null || find . -name '*.sh' -not -path '*/node_modules/*')
	cd $(EXT) && for f in *.js tests/*.js; do node --check $$f || exit 1; done
	python3 -m py_compile $(EXT)/*.py $(EXT)/tools/*.py scripts/*.py

test:
	cd $(EXT) && npm test
	cd $(EXT) && python3 -m unittest discover -s tests -p 'test_*.py'

check:
	python3 scripts/check_package.py $(EXT)

dist: check
	rm -rf dist/$(EXT)-$(VERSION) && mkdir -p dist/$(EXT)-$(VERSION)
	for f in $$(python3 scripts/check_package.py $(EXT) --files) install.sh uninstall.sh VERSION README.md CHANGELOG.md; do \
	  mkdir -p dist/$(EXT)-$(VERSION)/$$(dirname $$f); cp $(EXT)/$$f dist/$(EXT)-$(VERSION)/$$f; done
	cp LICENSE NOTICE.md dist/$(EXT)-$(VERSION)/
	tar -C dist -czf dist/$(EXT)-$(VERSION).tar.gz $(EXT)-$(VERSION)
	@echo "built dist/$(EXT)-$(VERSION).tar.gz"

install:
	sudo ./install.sh $(EXT)
uninstall:
	sudo ./uninstall.sh $(EXT)
clean:
	rm -rf dist $(EXT)/node_modules

# Auto-increment patch version from latest tag
AUTO_VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' | awk -F. '{printf "v%s.%s.%d", $$1, $$2, $$3+1}' || echo "v0.0.1")

# Capture positional argument (the word after the target)
ARG := $(filter-out push release clean help,$(MAKECMDGOALS))
VERSION = $(or $(ARG),$(AUTO_VERSION))
MSG = $(ARG)

# Catch-all to prevent "No rule to make target" for positional args
%::
	@true

.PHONY: push release clean help

## push: Commit and push code (usage: make push 'commit message')
push:
	@if [ -z "$(MSG)" ]; then echo "Usage: make push 'commit message'"; exit 1; fi
	git add .
	git commit -m "$(MSG)"
	git push origin main

## release: Bump version in __about__.py, tag, push, trigger CI (usage: make release [version])
release:
	@echo "==> Releasing $(VERSION)"
	sed -i.bak 's/__version__ = ".*"/__version__ = "$(patsubst v%,%,$(VERSION))"/' pybin/__about__.py && rm -f pybin/__about__.py.bak
	git add .
	git commit -m "release: $(VERSION)"
	@if git rev-parse "$(VERSION)" >/dev/null 2>&1; then \
		echo "==> Tag $(VERSION) exists, replacing..."; \
		git tag -d "$(VERSION)"; \
		git push origin ":refs/tags/$(VERSION)" 2>/dev/null || true; \
	fi
	git tag $(VERSION)
	git push origin main
	git push origin $(VERSION)
	@echo "==> Released $(VERSION)"
	@echo "https://github.com/zengzhifei/pybin/releases"

## clean: Remove build artifacts
clean:
	rm -rf .python .venv .uv build pybin.egg-info pybin/__pycache__

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'

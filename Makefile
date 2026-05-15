VERSION := $(shell grep __version__ pybin/__about__.py | cut -d'"' -f2)

push:
	git add -A
	git commit
	git push origin main

release:
	git add -A
	git commit || true
	@new_version=$$(echo $(VERSION) | awk -F. '{print $$1"."$$2"."$$3+1}'); \
	sed -i.bak "s/__version__ = \"$(VERSION)\"/__version__ = \"$$new_version\"/" pybin/__about__.py && \
	rm -f pybin/__about__.py.bak; \
	git add pybin/__about__.py; \
	git commit -m "bump version to $$new_version"; \
	git push origin main
	@v=$$(grep __version__ pybin/__about__.py | cut -d'"' -f2); \
	git push origin :refs/tags/v$$v 2>/dev/null || true; \
	git tag -d v$$v 2>/dev/null || true; \
	git tag v$$v; \
	git push origin main v$$v; \
	echo "https://github.com/zengzhifei/pybin/actions"; \
	echo "https://github.com/zengzhifei/pybin/releases"; \
	echo "Released v$$v."

rr:
	git add -A
	git commit || true
	git push origin main
	@v=$$(grep __version__ pybin/__about__.py | cut -d'"' -f2); \
	git push origin :refs/tags/v$$v 2>/dev/null || true; \
	git tag -d v$$v 2>/dev/null || true; \
	git tag v$$v; \
	git push origin main v$$v; \
	echo "https://github.com/zengzhifei/pybin/actions"; \
	echo "https://github.com/zengzhifei/pybin/releases"; \
	echo "Released v$$v."

.PHONY: push release rr

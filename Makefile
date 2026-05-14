VERSION := $(shell grep __version__ pybin/__about__.py | cut -d'"' -f2)

push:
	git add -A
	git commit
	git push origin main

release:
	git add -A
	git commit
	@new_version=$$(echo $(VERSION) | awk -F. '{print $$1"."$$2"."$$3+1}'); \
		sed -i.bak "s/__version__ = \"$(VERSION)\"/__version__ = \"$$new_version\"/" pybin/__about__.py && \
		rm -f pybin/__about__.py.bak; \
		v=$$(grep __version__ pybin/__about__.py | cut -d'"' -f2); \
		git add pybin/__about__.py; \
		git commit -m "bump version to $$v"; \
		git tag "v$$v"; \
		git push origin main "v$$v"; \
		echo "Released v$$v."

.PHONY: push release

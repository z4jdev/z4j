# z4j

[![PyPI version](https://img.shields.io/pypi/v/z4j.svg)](https://pypi.org/project/z4j/)
[![Python](https://img.shields.io/pypi/pyversions/z4j.svg)](https://pypi.org/project/z4j/)
[![License](https://img.shields.io/pypi/l/z4j.svg)](https://github.com/z4jdev/z4j/blob/main/LICENSE)

The all-in-one z4j umbrella package.

Installs the brain server plus an opinionated set of agent extras
through a single `pip install z4j`. Pin extras for the framework
and engines your stack uses; everything cross-versions to the
same z4j release line.

## Install

```bash
pip install z4j
z4j serve
```

For an existing app, install the framework + engine extras you
need (e.g. `pip install 'z4j[django,celery]'`).

## Documentation

Full docs at [z4j.dev](https://z4j.dev).

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE). Note: only the brain
is AGPL; the agent packages your application imports are
Apache-2.0 each, so your application code is never AGPL-tainted.

## Links

- Homepage: https://z4j.com
- Documentation: https://z4j.dev
- PyPI: https://pypi.org/project/z4j/
- Issues: https://github.com/z4jdev/z4j/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: security@z4j.com (see [SECURITY.md](SECURITY.md))

## 2.0.0 (2026-10-09)

#### Breaking Changes

* **ci:** replace Node.js tooling with Go tools (#13) ([94665ab6](https://github.com/larryf1/jwtoken-tester/commit/94665ab694358cd3aad56ebf312763b2f7d5587c))
```

* feat(ci)!: replace Node.js tooling with Go tools

Remove the entire Node.js footprint (package.json, package-lock.json,
.npmrc, .nvmrc, commitlint.config.js, node_modules, tools/npm-stub) from
the build, CI, release, and contribution path.

Own commit linting and release cutting with two off-the-shelf Go tools
run via go run: conventionalcommit/commitlint (.commitlint.yaml) and
go-semantic-release (.semrelrc + changelog template). Add a govulncheck
CI job over the shipped Go module in place of the npm-deps audit, and a
dry_run dispatch input on the release workflow so it can be validated
without writing.

BREAKING CHANGE: contributors no longer need Node.js/npm; commit linting
runs via `make lint-commits`.

Signed-off-by: larry1 <larryf1@gmail.com>

* feat(parser): implement lexer for conventional commit parsing

Signed-off-by: Larry Finkelstein <77911806+larryf1@users.noreply.github.com>

---------

Signed-off-by: larry1 <larryf1@gmail.com>
Signed-off-by: Larry Finkelstein <77911806+larryf1@users.noreply.github.com>
```

#### Chores

* **specs:** add baseline specifications for jwtoken-tester functionality ([1c94d659](https://github.com/larryf1/jwtoken-tester/commit/1c94d6593e34ed45c346bbf945953bf5f2354920))
* **deps:** add npm stub override in package.json and update package-lock.json ([51279bb2](https://github.com/larryf1/jwtoken-tester/commit/51279bb259f6694dc80e11adb6c7a82ed0012e38))
* **deps:** bump @commitlint/config-conventional from 21.2.2 to 21.2.3 (#10) ([77f53e37](https://github.com/larryf1/jwtoken-tester/commit/77f53e37d2d737f3127c0a1957bb10d2a4a8daca))
* **deps:** bump @commitlint/cli from 21.2.2 to 21.2.3 (#11) ([9aab854e](https://github.com/larryf1/jwtoken-tester/commit/9aab854e68ce93f5200a3c7e4fa03f93f7d30e6c))

#### CI

* enhance CI workflows with SHA-pinning for actions and add security audits (#12) ([788e2a14](https://github.com/larryf1/jwtoken-tester/commit/788e2a141948714c86cc925314e08442643fe34b))
* add npm-10 lockfile sync gate and pin npm version ([910462f0](https://github.com/larryf1/jwtoken-tester/commit/910462f00c1da42224ec51e463a73e96f745f1da))


# [1.3.0](https://github.com/larryf1/jwtoken-tester/compare/v1.2.0...v1.3.0) (2026-09-14)


### Bug Fixes

* **commitlint:** set maximum body line length to 200 characters ([dcfdda9](https://github.com/larryf1/jwtoken-tester/commit/dcfdda91cf01d74cbf7d4ad5478a22773faee8c5))


### Features

* **dco:** add DCO configuration to skip sign-off for known bots and allow remediation commits ([3bf51ad](https://github.com/larryf1/jwtoken-tester/commit/3bf51ad0e090a6fb8584c3e7a9e3d75c5ad378e9))

# [1.2.0](https://github.com/larryf1/jwtoken-tester/compare/v1.1.0...v1.2.0) (2026-09-12)


### Features

* **rate-limiting:** add configurable rate limiting parameters and request ID handling ([6342fe0](https://github.com/larryf1/jwtoken-tester/commit/6342fe097fd71d7a4adf1419411c1f89ee7ed4f7))
* **security:** implement rate limiting and security headers in server ([81a0fb8](https://github.com/larryf1/jwtoken-tester/commit/81a0fb8bd98716062bf488599a31f0ff31ac4a24))

# [1.1.0](https://github.com/larryf1/jwtoken-tester/compare/v1.0.1...v1.1.0) (2026-09-11)


### Features

* **docker:** enhance Dockerfile to include versioning and OCI labels for better metadata ([1e6f74b](https://github.com/larryf1/jwtoken-tester/commit/1e6f74b8355602827f256046411535deb90369e4))

## [1.0.1](https://github.com/larryf1/jwtoken-tester/compare/v1.0.0...v1.0.1) (2026-09-11)


### Bug Fixes

* **versioning:** enhance versioning logic to use git describe for builds and update README with versioning details ([d3bb03a](https://github.com/larryf1/jwtoken-tester/commit/d3bb03aaf351b05938bfafe4f6663951ab81df8d))

# 1.0.0 (2026-09-10)


### Bug Fixes

* improve resource cleanup in tests and simplify keyring initialization ([bffcd52](https://github.com/larryf1/jwtoken-tester/commit/bffcd52ace52d501a6c55d4b2d26b83f258f844c))
* update GitHub Actions to use latest versions of checkout and setup actions ([8be8fbf](https://github.com/larryf1/jwtoken-tester/commit/8be8fbf66c88c03b12aa22e67b25715e6ba9b53e))


### Features

* add Docker support with Dockerfile and docker-compose for jwtoken-tester and demo service ([10bb1a8](https://github.com/larryf1/jwtoken-tester/commit/10bb1a8e65debfb337cf2400a49adc38b3c3ceaf))
* add JWKByKID endpoint to retrieve keys by kid and update README ([6c6bce4](https://github.com/larryf1/jwtoken-tester/commit/6c6bce4c6fa0a801cab479d68d8d0da18a023fb5))
* add testing framework with server setup and token validation tests ([0eb07ec](https://github.com/larryf1/jwtoken-tester/commit/0eb07ecf8572c78a2675472573e974de7aef7474))
* add versioning support and update server to expose version endpoint ([0849607](https://github.com/larryf1/jwtoken-tester/commit/084960727e4ac483b7e26a2677f5368f4b794fb9))
* implement command-line interface for serving and printing JWTs with enhanced configuration options ([7eab9a4](https://github.com/larryf1/jwtoken-tester/commit/7eab9a461c9ba80e07a80519722fa2d66ee06a8a))
* implement support for multiple signing algorithms (RS256, ES256, EdDSA) in keyring ([24e65bc](https://github.com/larryf1/jwtoken-tester/commit/24e65bc24aef2fff10117f7e975fb05b5571784b))
* update Makefile to include 'serve' command in run target ([e0f047c](https://github.com/larryf1/jwtoken-tester/commit/e0f047c79d743dfcacb638412c13b397c8f9d011))
* update proposal and README to reflect completion of M3 and M4 tasks ([18e6258](https://github.com/larryf1/jwtoken-tester/commit/18e6258f9779870909e76d5f66f7565113f9af7d))
* update README and server to document and support JWK retrieval by kid ([7835441](https://github.com/larryf1/jwtoken-tester/commit/783544106706b370ddda4c6128ad6f9fe5519be1))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project setup

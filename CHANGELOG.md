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

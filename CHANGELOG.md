# Changelog

All notable changes to this project are documented here.

This project follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version numbers follow npm package releases.

## [Unreleased]

## [1.1.0] - 2026-05-13

### Added

- Add advisory pre-scan supply-chain health checks for package manager release-age gates and pinned dependency ranges.

## [1.0.1] - 2026-05-13

### Fixed

- Fix scanner fail-open cases so parse and scan errors are surfaced without hiding compromised package findings.

### Changed

- Refresh the bundled compromised package database from the Snyk advisory.

## [1.0.0] - 2026-05-13

### Added

- Initial npm package release for `mini-shai-hulud-scanner`.
- Scan npm, pnpm, yarn, and bun lockfiles for known compromised package versions from the TanStack mini Shai-Hulud incident.
- Report affected package counts, clean package counts, lockfile counts, Snyk advisory IDs, and advisory URLs.
- Support `npx mini-shai-hulud-scanner` and global npm installation.
- Add parser test coverage with clean and compromised fixture lockfiles.
- Add release scripts, package metadata, MIT license, and bundled compromised package database.

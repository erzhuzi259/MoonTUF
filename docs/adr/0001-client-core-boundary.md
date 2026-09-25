# ADR 0001: Keep update transport outside the trust core

Status: Accepted (2026-09-25)

## Context

TUF protects software-update metadata and artifacts, but consumers range from
desktop applications and package managers to offline gateways and firmware
agents. Those hosts have incompatible download, storage and installation needs.

## Decision

MoonTUF provides deterministic metadata verification and trusted-state
transitions. Callers provide bounded bytes, a fixed update start time, and
storage/fetch adapters. MoonTUF does not perform network I/O, manage private
keys or install target files. The first profile is JSON, Ed25519 and SHA-256.

## Consequences

The same library can run on multiple MoonBit targets and in offline tests. The
host remains responsible for atomically persisting accepted state and never
using candidate bytes before verification. A future network/CLI adapter can
be separate without changing trust semantics.

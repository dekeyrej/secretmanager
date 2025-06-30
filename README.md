# SecretManager

![MIT License](https://img.shields.io/github/license/dekeyrej/secretmanager)
![Last Commit](https://img.shields.io/github/last-commit/dekeyrej/secretmanager)
![Repo Size](https://img.shields.io/github/repo-size/dekeyrej/secretmanager)
[![PyPI](https://img.shields.io/pypi/v/dekeyrej-secretmanager)](https://pypi.org/project/dekeyrej-secretmanager/)
![Build Status](https://github.com/dekeyrej/secretmanager/actions/workflows/publish-to-test-pypi.yml/badge.svg)

### Important note!

_With no gymnastics_, this works with Python 3.12 and earlier. It may fail with Python 3.13 (or later) — [see details for a fix here](python_ssl_summary.md)

## Why SecretManager?

Where does the first secret live?

Kubernetes provides mechanisms for working with secrets—but not securely storing or transporting them. Traditional approaches often leave “Secret Zero” exposed in environment variables, mounted volumes, or static keys.

This project implements a **Zero Trust**, **ephemeral authentication** solution for managing your Kubernetes secrets securely, leveraging **HashiCorp Vault** as an encryption-as-a-service backend.

Originally built to harden my homelab, this is a practical tool for anyone facing that lingering security question: _“How do I bootstrap secrets without leaking them?”_

## Design Principles

- Secrets stored as Vault-encrypted ciphertext in Kubernetes
- Vault Transit used as the encryption backend (AES-256)
- Kubernetes auth ensures **no standing credentials** are ever stored
- Vault tokens are **short-lived (10s or less)** to reduce exposure
- AES key material **never touches disk or memory**
- Automated **key lifecycle hygiene** via Vault key rotation

## Project Components 

- `**encryptonator.py**`: One-time or occasional encryptor for secrets JSON; stores ciphertext in Kubernetes Secret after vault-encrypted transit encryption.
- `**kubevault_example.py**`: Reads ciphertext from Kubernetes and decrypts it via Vault Transit — intended as an init routine for microservices. Secrets live only in ephemeral Python objects.
- `**recryptonator.py**`: Rotates your Vault Transit key. Pulls ciphertext, decrypts, rotates key, re-encrypts with new key, pushes new ciphertext to Kubernetes. Designed to run as a CronJob (mine is daily at 3:00 AM).

All connection and secret metadata are defined in config dictionaries. Policies follow a **least-privilege** model (see `encryptonator/my-app-policy.hcl`).

## A Brief History of Failing Forward

This repo evolved through a series of failed or insecure (but educational) strategies:

1. **Secrets in image**: wildly insecure, but good for offline dev.
2. **Encrypted SecureDicts**: better, but required bundling an AES key.
3. **"One secret to rule them all"**: stored whole dict in Kubernetes, loaded at runtime, then wiped—still shaky.
4. **YAML-based env config split**: functional and easy but insecure.
5. **This**: Vault + short-lived auth + encryption-as-a-service + automatic key rotation = _peace of mind_.

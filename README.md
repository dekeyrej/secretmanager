# SecretManager

![MIT License](https://img.shields.io/github/license/dekeyrej/secretmanager)
![Last Commit](https://img.shields.io/github/last-commit/dekeyrej/secretmanager)
![Repo Size](https://img.shields.io/github/repo-size/dekeyrej/secretmanager)
[![PyPI](https://img.shields.io/pypi/v/dekeyrej-secretmanager)](https://pypi.org/project/dekeyrej-secretmanager/)
[![codecov](https://codecov.io/gh/dekeyrej/secretmanager/branch/main/graph/badge.svg)](https://codecov.io/gh/dekeyrej/secretmanager)
![Build Status](https://github.com/dekeyrej/secretmanager/actions/workflows/ci.yml/badge.svg)

### Important note!

_With no gymnastics_, this works with Python 3.12 and earlier. It may fail with Python 3.13 (or later) — [see details for a fix here](./docs/python_ssl_summary.md)

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

- The first secret: [`**encryptonator.py**`](./tools/encryptonator.py): One-time or occasional encryptor for JSON secrets; takes JSON from a file, or on the commandline, logs into vault via Kubenetes authentication, encrypts the JSON with transit security, and stores ciphertext in a Kubernetes secret.
- Accessing secrets securely: [`**kubevault_example.py**`](./examples/kubevault_example.py): logs into vault via Kubenetes authentication, reads ciphertext from a Kubernetes secret, and decrypts to JSON with transit security — intended as an init routine for microservices. Secrets live only in ephemeral Python objects.
- Eternal security: [`**recryptonator.py**`](./tools/recryptonator.py): Rotates your Vault Transit key. Logs into Vault using Kubernetes authetication, pulls ciphertext from Kubenetes secret, decrypts using vault transit security, tells vault to rotate the encryption key, re-encrypts with new key, pushes new ciphertext back to the Kubernetes secret. Designed to run as a CronJob (mine is monthly at 3:00 AM on the first day of the month). Your frequency may vary depending on how often you are accessing your secrets - in my usage, I only need to access the secrets a couple of times per month.

All connection and secret metadata are defined in config dictionaries. Policies follow a **least-privilege** model (see `examples/my-app-policy.hcl`).

## Setting up Vault with Kubernetes Authetication vai Ansible
See my [ansible](https://github.com/dekeyrej/ansible) repo (I know, it's a lot.)

Two playbooks are salient here:
1. [the-delving-of-moria.yaml](https://github.com/dekeyrej/ansible/blob/main/playbooks/the-delving-of-moria.yaml) which performs all of the initial vault setup via a series of roles:
  - copies the certificate authority's public certificate `certificate-authority-copy-to-host`,
  - adds Vault sources to ubuntu's apt `apt-add-source-vault`, 
  - apt installs `[vault, python3-kubernetes, python3-hvac]` via `apt-add-packages`, 
  - installs kubectl `kubernetes-kubectl-install`,
  - generates suitable SSL certs for vault (this is important. note the parameters) `certificate-authority-generate-certs`,
  - configures vault (SSL certs, and for gcpckms auto-unlocking) `vault-configure`, and
  - initalizes the vault `vault-initialize`
2. [the-forming-of-the-fellowship.yaml](https://github.com/dekeyrej/ansible/blob/main/playbooks/the-forming-of-the-fellowship.yaml) which creates the Kubernetes (microk8s) cluster, and in the penultimate play `Configure vault support kubernetes authentication and transit secrets` sets up Kubernetes authentication with the vault via a few more roles:
  - configure the ubuntu user on the vault to access the kubernetes cluster and to connect to the vault from the commandline `user-ubuntu-configure`,
  - copy the kubernetes config file from the cluster `kubernetes-fetch-config-nolocal`, and
  - perform the final set of complex actions on both the cluster and the vault `vault-configure-for-kubevault`.

## A Brief History of Failing Forward

This repo evolved through a series of failed or insecure (but educational) strategies:

1. **Secrets in image**: wildly insecure, but good for offline dev.
2. **Encrypted SecureDicts**: better, but required bundling an AES key.
3. **"One secret to rule them all"**: stored whole dict in Kubernetes, loaded at runtime, then wiped—still shaky.
4. **YAML-based env config split**: functional and easy but insecure.
5. **This**: Vault + short-lived auth + encryption-as-a-service + automatic key rotation = _peace of mind_.

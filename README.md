# SecretManager

### Important note!

_With no gymnastics_, this works with Python 3.12 and earlier.  It may fail with Python 3.13 (or later) - [see details for a fix here](python_ssl_summary.md) 

## Why a SecretManager?

I've been considering the "where does the first secret live?" question for a while now.  Kubernetes is not a secrets management platform, though it provides some functionailty in that regard. The 'typical' solutions for pure Kubernetes-controlled secrets still leave that 'first secret' exposed - somewhere.  This library is my latest attempt at protecting that first secret inside HashiCorp's vault.

## History (well _my_ history with this question)

- Store all of the secrets in a JSON 'dict', and copy that into each of my images.  Works, but wildly insecure - but also very handy for development without access to the Kubernetes cluster.

- Create a library to manage (encrypt/decrypt) 'SecureDicts' -- JSON 'dict' with plaintext keys, and AES256 encrypted values. dict is now _reasonably_ secure, but I was left with trying to provide the AES256 key to the running container. At this point I implemented code to (1) store the AES256 key as a Kubernetes secret, (2) access that secret directly from the secret (no mounting, no environment variables), and (3) decrypt the secret values. Works, more secure, and a bit easier to understand from a code development standpoint - but the AES256 key is still 'exposed'. (perhaps the basis for a future method - reading the AES256 key from the Vault?)

- Cram the whole JSON dict into one secret, read that secret and "Bob's your uncle...". My base class for my microservices reads the secret on initialization, extracts the values it requires, and then destroys the objects that accessed the secret. Works, performant, obscured, but not really secure - though there are no traces of the secret visible in the images, or container other than the couple of values required for the particular microservice.

- Switched values from JSON to YAML format (easier to manage the plaintext), broke the YAML into three chunks - common configuration (no really sensitive secrets - used by every microservice), app-specific configuration (no really sensitive values - only required by a couple of the microservices), and secrets (three really sensitive values - used by a couple of microservices). The two sets of configuration values were mounted into the containers as environment variables, as were the individually necessary secrets.  Works, relatively easy to manage, really insecure.

Which brings us up to date...

## The _latest_ Concept

This current scheme integrates Kubernetes secrets to store the ciphertext (AES256 encrypted) version of the JSON dict. It also integrates with a self-managed (doesn't have to be) HashiCorp Vault configured for kubernetes authentication, and Transit key-based encrypt/decrypt as a service with rotable keys.  All of the necessary functions are wrapped into the SecretManager package.

Beyond the library and the Vault, there are three Python components that comprise the solution:

- **encryptonator.py** is run once* to read the plaintext file (text-based, but no formatting assumed), encrypt that file with the transit key, and load the ciphertext into the target Kubernetes secret. (once* at startup, and anytime the base plaintext is changed)

- **kubevault_example.py** which is a surrogate implementation for reading the ciphertext from the Kubernetes secret, and decrypting the secret resulting in a usable set of values.

- **recryptonator.py** which implements the key rotation which is central to this new, more secure implementation. The recryptonator _periodically_ reads the ciphertext from the Kubernetes secret, decrypts it, rotates the transit key, reencrypts the secrets with the new key, and stores the new ciphertext back in the Kubernetes secret. The periodicity is achieved by running a CronJob in the Kubernetes cluster - in the example - every day at 3:00AM. It can certainly be run more frequently as the whole process takes no more tham 150ms (with substantial logging).


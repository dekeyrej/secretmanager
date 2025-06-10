from setuptools import find_packages, setup

setup(
    name='secretmanager',
    packages=find_packages(include=['secretmanager']),
    version='1.0.0',
    description='Multi-mode secret management library for Kubernetes and Vault',
    author='Joseph S. DeKeyrel',
    license='MIT',
    install_requires=[],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    test_suite='tests',
)
---
title: Kubernetes Enumeration
description: Kubernetes cluster security and infrastructure enumeration guide
---

The Hatiyar Kubernetes enumeration suite provides comprehensive visibility into your Kubernetes clusters. Each module focuses on specific K8s resources, providing detailed discovery, configuration analysis, and security assessments.

## Available Modules

| Module | Description |
|--------|-------------|
| **Enum** | Comprehensive cluster enumeration orchestrator (runs all specialized modules) |
| **K8s Pods** | Pod-specific enumeration: containers, volumes, security contexts, resources |
| **Secrets** | Secrets enumeration and extraction |
| **Volumes** | Storage enumeration: PVs, PVCs, StorageClasses |
| **Namespaces** | Namespace enumeration with resource quotas and limits |

## Getting Started

```bash
# Start hatiyar shell
hatiyar shell

# List available Kubernetes modules
hatiyar> ls platforms.k8s

# Use a specific module
hatiyar> use platforms.k8s.enum
```

---

## General Kubernetes Setup

This setup applies to all Kubernetes enumeration modules.



### 1. Configure Kubernetes Access

Choose one of these authentication methods:

#### Option A: Kubeconfig File (Recommended)

The most common method using your existing kubeconfig:

```bash
# Default kubeconfig location: ~/.kube/config
# No additional setup needed if you can already use kubectl
set KUBECONFIG ~/.kube/config
set CONTEXT <name-of-context>
```

Verify access:
```bash
kubectl cluster-info
kubectl get nodes
```

#### Option B: In-Cluster Authentication

If running hatiyar inside a Kubernetes pod:

```bash
# Use service account token automatically
# Set AUTH_METHOD to "in-cluster" in hatiyar
```

#### Option C: Token Authentication

Using a service account token:

```bash
# Get token from service account
kubectl -n kube-system get secret $(kubectl -n kube-system get sa default -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d

# Set in hatiyar:
set API_SERVER https://your-cluster:6443
set TOKEN your-token-here
set AUTH_METHOD token
```

#### Option D: Client Certificates

Using certificate-based authentication:

```bash
set API_SERVER https://your-cluster:6443
set CLIENT_CERT_PATH /path/to/client.crt
set CLIENT_KEY_PATH /path/to/client.key
set CA_CERT_PATH /path/to/ca.crt
set AUTH_METHOD cert
```


### 2. Testing with Kind (Kubernetes in Docker)

Another lightweight option for local testing:

```bash
# Install Kind
# https://kind.sigs.k8s.io/docs/user/quick-start/

# Create cluster
kind create cluster --name hatiyar-test

# Verify
kubectl cluster-info --context kind-hatiyar-test

# Cleanup
kind delete cluster --name hatiyar-test
```

---

## Usage

#### Basic Usage

```bash
hatiyar> use platforms.k8s.pods
hatiyar> set namespace default
hatiyar> run
```

#### Configuration Options

```bash
hatiyar> use platforms.k8s.pods
hatiyar> show options

# Target specific namespace
hatiyar> set namespace kube-system

# Or enumerate all namespaces
hatiyar> set all_namespaces true

# Configure output file
hatiyar> set OUTPUT_FILE k8s_pods_results.json

# Run enumeration
hatiyar> run
```

### Contributing New K8s Modules
Want to add support for additional K8s resources? See our [Contributing Guide](/hatiyar/guides/contribution/)
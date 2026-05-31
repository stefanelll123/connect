# Sentinel UI — Kubernetes Port-Forward Access Guide

## Overview

The Sentinel Node's local web UI (`/ui/*`) is **bound exclusively to `127.0.0.1`
inside the pod** by default. It is not exposed via Kubernetes Service, Ingress,
or NodePort. This prevents accidental exposure to cluster-internal or external
networks.

---

## Accessing the UI via Port-Forward

Use `kubectl port-forward` to tunnel a local port to the pod:

```bash
kubectl port-forward pod/<sentinel-pod-name> 8081:8080 -n <namespace>
```

Then open in your browser:

```
http://127.0.0.1:8081/ui/health
http://127.0.0.1:8081/ui/did
http://127.0.0.1:8081/ui/credentials
http://127.0.0.1:8081/ui/logs
```

### Finding the Pod Name

```bash
kubectl get pods -n <namespace> -l app=sentinel
```

---

## Automated Health Monitoring

For automated readiness checks from within the cluster, call the
non-UI `/health/ready` endpoint directly via `kubectl exec` rather than
using the UI:

```bash
kubectl exec -n <namespace> <sentinel-pod-name> -- \
  curl -sf http://127.0.0.1:8080/health/ready
```

This avoids the need to port-forward for automated probes.

---

## Enabling Token Authentication

Set `SENTINEL_UI_AUTH=token` and provide a strong random token via a
Kubernetes Secret:

```yaml
# sentinel-ui-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: sentinel-ui-secret
  namespace: <namespace>
type: Opaque
stringData:
  SENTINEL_UI_TOKEN: "<generate with: openssl rand -base64 32>"
```

Mount as environment variables in the Sentinel Deployment:

```yaml
envFrom:
  - secretRef:
      name: sentinel-ui-secret
env:
  - name: SENTINEL_UI_AUTH
    value: "token"
```

Then include the token in the `Authorization` header when accessing via
port-forward:

```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8081/ui/health
```

---

## Security Warnings

- **Never expose `/ui` via an Ingress or NodePort** in any environment.
  The UI contains identity information (DID, key fingerprints) and live
  request logs.

- If `SENTINEL_UI_HOST` is set to anything other than `127.0.0.1` while
  `SENTINEL_UI_AUTH=none`, the Sentinel logs a **CRITICAL** warning at
  startup and increments the `sentinel_insecure_config_warnings_total`
  metric. This configuration should only be used in isolated dev
  environments (e.g., Docker Compose without external exposure).

- **Close the browser** after use. The UI has no session expiry.
  If browser is shared, use `SENTINEL_UI_AUTH=token` to prevent access
  by other local users.

- The `SENTINEL_UI_TOKEN` or `SENTINEL_UI_PASSWORD` **must never be
  logged**. The Sentinel logs the `auth_mode` (e.g., `token`) but never
  the credential value.

---

## Basic Auth Mode

```yaml
env:
  - name: SENTINEL_UI_AUTH
    value: "basic"
  - name: SENTINEL_UI_PASSWORD
    valueFrom:
      secretKeyRef:
        name: sentinel-ui-secret
        key: SENTINEL_UI_PASSWORD
```

The username is always `sentinel`. Access via browser will trigger the
browser's built-in Basic Auth prompt.

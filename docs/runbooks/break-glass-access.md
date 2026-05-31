# Break-Glass Emergency Access

**Purpose**: Emergency access to production Vault and cluster when normal access paths are unavailable.  
**Rule**: Minimum **two persons** from different teams must be present. All actions are logged.

---

## 1. Break-Glass Conditions

Break-glass access is ONLY authorised when:
- Normal service accounts are locked out (Vault sealed, OIDC provider down)
- Active security incident requiring immediate intervention
- Disaster recovery requiring cluster-level access

**Prohibited**: Using break-glass for routine maintenance or convenience.

---

## 2. Emergency Vault Access

### Physical Emergency Key

A Vault unseal key shard is stored in a **physical safe** (location known to Security Lead and CTO only).  
Recovery procedure:
1. At least two authorised persons physically retrieve the safe key
2. Combined Shamir shards unseal Vault:
   ```bash
   vault operator unseal <SHARD_1>
   vault operator unseal <SHARD_2>
   vault operator unseal <SHARD_3>
   ```
3. All unseal operations are automatically logged in Vault audit log

### Digital Emergency Token (Break-Glass Vault Token)

An emergency long-lived token is stored encrypted in:
- HSM-backed KMS key: `arn:aws:kms:eu-west-1:ACCOUNT:key/BREAK-GLASS-KEY-ID`
- Access requires 2 IAM principals' approval via AWS IAM Access Analyzer

```bash
# Retrieve break-glass token (requires 2FA + second approver in Slack approval workflow)
aws secretsmanager get-secret-value \
  --secret-id sentinel/break-glass/vault-token \
  --region eu-west-1

export VAULT_TOKEN="<retrieved token>"
export VAULT_ADDR="https://vault.internal:8200"

# Immediately rotate after use
vault token renew ${VAULT_TOKEN}
```

---

## 3. Emergency Kubernetes Access

If OIDC/RBAC is unavailable:
```bash
# Use static kubeconfig stored in S3 (encrypted at rest)
aws s3 cp s3://sentinel-break-glass/kubeconfig.enc /tmp/kc.enc
aws kms decrypt --ciphertext-blob fileb:///tmp/kc.enc \
  --output text --query Plaintext | base64 -d > /tmp/kubeconfig
export KUBECONFIG=/tmp/kubeconfig
kubectl auth whoami
```

---

## 4. PagerDuty Escalation

For P1 incidents requiring break-glass:

| Role | Contact |
|------|---------|
| Security Lead | `@security-lead` on Slack + PagerDuty P1 escalation |
| CTO | Backup approver if Security Lead unavailable |
| Platform Lead | Cluster access co-approver |

PagerDuty incident required BEFORE break-glass access is used.  
Break-glass without active PD incident = policy violation.

---

## 5. Logging and Accountability

ALL break-glass activities must be documented within 1 hour:
1. Open a GitHub issue in the internal security repo: `sentinel/break-glass-YYYY-MM-DD`
2. Record: who, when, why, what commands ran, outcome
3. Notify DPO if PII was accessed
4. Rotate the break-glass token after use:
   ```bash
   vault token revoke ${VAULT_TOKEN}
   # Generate new break-glass token and re-encrypt to S3
   ```

---

## 6. Token Rotation Schedule

Break-glass tokens are rotated every **90 days** via automated pipeline.  
Manual rotation: `make rotate-break-glass` (requires 2-person approval in GitHub Actions)

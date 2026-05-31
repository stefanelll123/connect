#!/bin/bash
# =============================================================================
# Producer user_data — EC2 bootstrap for the producer sentinel node.
# Installs Docker, clones repo, writes secrets env, then delegates to
# tests/terraform/scripts/producer-setup.sh.
#
# Terraform templatefile variables:
#   ${aws_region} ${git_repo_url} ${git_token} ${github_repository}
#   ${hub_private_ip} ${postgres_password} ${redis_password}
#   ${secret_storage_master_key} ${sentinel_passphrase} ${ssm_prefix}
#   ${docker_hub_username} ${image_tag}
# =============================================================================
set -euo pipefail
exec > >(tee /var/log/connect-bootstrap.log | logger -t connect-producer) 2>&1
echo "=== Connect Producer Bootstrap — $(date -u) ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl ca-certificates gnupg lsb-release unzip jq

# ── Install AWS CLI v2 ───────────────────────────────────────────────────────
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp
/tmp/aws/install
rm -rf /tmp/awscliv2.zip /tmp/aws

# ── Install Docker ───────────────────────────────────────────────────────────
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
echo "✓ Docker $(docker --version)"

# ── Clone repository ─────────────────────────────────────────────────────────
GIT_TOKEN="${git_token}"
GIT_REPO="${git_repo_url}"
if [ -n "$GIT_TOKEN" ]; then
  CLONE_URL="https://$GIT_TOKEN@$${GIT_REPO#https://}"
else
  CLONE_URL="$GIT_REPO"
fi
git clone --depth 1 "$CLONE_URL" /opt/connect
echo "✓ Repo cloned"

# ── Fetch this instance's private IP from EC2 metadata (IMDSv2) ────────────────
TOKEN=$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
  http://169.254.169.254/latest/api/token)
PRODUCER_PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/local-ipv4)

# ── Write secrets env file ───────────────────────────────────────────────────
cat > /opt/connect/.env.producer << ENVEOF
AWS_DEFAULT_REGION=${aws_region}
SSM_PREFIX=${ssm_prefix}
HUB_PRIVATE_IP=${hub_private_ip}
PRODUCER_PRIVATE_IP=$PRODUCER_PRIVATE_IP
DOCKER_HUB_USERNAME=${docker_hub_username}
IMAGE_TAG=${image_tag}
POSTGRES_PASSWORD=${postgres_password}
REDIS_PASSWORD=${redis_password}
SECRET_STORAGE_MASTER_KEY=${secret_storage_master_key}
SENTINEL_PASSPHRASE=${sentinel_passphrase}
GITHUB_REPOSITORY=${github_repository}
GIT_TOKEN=${git_token}
ENVEOF
chmod 600 /opt/connect/.env.producer
echo "✓ Env file written"

export PRODUCER_PRIVATE_IP
bash /opt/connect/tests/terraform/scripts/producer-setup.sh
#!/bin/bash
# =============================================================================
# Hub user_data — EC2 bootstrap for the hub instance.
# Installs Docker + Node.js, clones repo, writes secrets env, then delegates
# to tests/terraform/scripts/hub-setup.sh for all heavy orchestration.
#
# Terraform templatefile variables:
#   ${aws_region} ${git_repo_url} ${git_token} ${github_repository}
#   ${postgres_password} ${redis_password} ${secret_storage_master_key}
#   ${hardhat_private_key} ${sentinel_passphrase} ${discovery_admin_api_key}
#   ${ssm_prefix} ${docker_hub_username} ${image_tag}
# =============================================================================
set -euo pipefail
exec > >(tee /var/log/connect-bootstrap.log | logger -t connect-hub) 2>&1
echo "=== Connect Hub Bootstrap — $(date -u) ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl ca-certificates gnupg lsb-release unzip jq \
  python3 python3-venv

# ── Install AWS CLI v2 ───────────────────────────────────────────────────────
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp
/tmp/aws/install
rm -rf /tmp/awscliv2.zip /tmp/aws
echo "✓ AWS CLI $(aws --version 2>&1 | head -1)"

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

# ── Install Node.js 20 (for contract deployment) ─────────────────────────────
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -qq nodejs
echo "✓ Node $(node --version)"

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

# ── Write secrets env file ───────────────────────────────────────────────────
# Fetch this instance's public IP from EC2 metadata (IMDSv2)
TOKEN=$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
  http://169.254.169.254/latest/api/token)
HUB_PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/public-ipv4)
HUB_PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/local-ipv4)

cat > /opt/connect/.env.hub << ENVEOF
AWS_DEFAULT_REGION=${aws_region}
SSM_PREFIX=${ssm_prefix}
HUB_PUBLIC_IP=$HUB_PUBLIC_IP
HUB_PRIVATE_IP=$HUB_PRIVATE_IP
DOCKER_HUB_USERNAME=${docker_hub_username}
IMAGE_TAG=${image_tag}
POSTGRES_PASSWORD=${postgres_password}
REDIS_PASSWORD=${redis_password}
SECRET_STORAGE_MASTER_KEY=${secret_storage_master_key}
HARDHAT_PRIVATE_KEY=${hardhat_private_key}
SENTINEL_PASSPHRASE=${sentinel_passphrase}
DISCOVERY_ADMIN_API_KEY=${discovery_admin_api_key}
GITHUB_REPOSITORY=${github_repository}
GIT_TOKEN=${git_token}
ENVEOF
chmod 600 /opt/connect/.env.hub
echo "✓ Env file written"

export HUB_PUBLIC_IP HUB_PRIVATE_IP
bash /opt/connect/tests/terraform/scripts/hub-setup.sh
# SSH key pair — created from a local public key so no manual console step is needed.
resource "aws_key_pair" "connect_test" {
  key_name   = "connect-test-key"
  public_key = file(var.ssh_public_key_path)
}

# ── Hub EC2 instance ─────────────────────────────────────────────────────────
# Runs: postgres, redis, hardhat (Anvil), discovery, governance, otel-collector.
# Also runs seed.py to deploy contracts and writes their addresses to SSM so
# that the producer and consumer can pick them up.

resource "aws_instance" "hub" {
  ami                         = data.aws_ssm_parameter.ubuntu_22_04_ami.value
  instance_type               = var.hub_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.hub.id]
  key_name                    = aws_key_pair.connect_test.key_name
  iam_instance_profile        = aws_iam_instance_profile.connect_ec2.name
  associate_public_ip_address = true

  root_block_device {
    volume_type = "gp3"
    volume_size = var.hub_volume_size_gb
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/user_data/hub.sh", {
    aws_region                = var.aws_region
    git_repo_url              = var.git_repo_url
    git_token                 = var.git_token
    github_repository         = var.github_repository
    postgres_password         = var.postgres_password
    redis_password            = var.redis_password
    secret_storage_master_key = var.secret_storage_master_key
    hardhat_private_key       = var.hardhat_private_key
    sentinel_passphrase       = var.sentinel_passphrase
    discovery_admin_api_key   = var.discovery_admin_api_key
    ssm_prefix                = var.ssm_prefix
  }))

  tags = { Name = "connect-test-hub", Role = "hub" }
}

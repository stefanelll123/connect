# ── Consumer EC2 instance ────────────────────────────────────────────────────
# Runs: sentinel-consumer.
# The Locust load tests also run on this instance (or can be run from the
# operator's machine by setting PRODUCER_URL / DISCOVERY_URL env vars).

resource "aws_instance" "consumer" {
  depends_on = [aws_instance.hub]

  ami                         = data.aws_ssm_parameter.ubuntu_22_04_ami.value
  instance_type               = var.node_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.consumer.id]
  key_name                    = aws_key_pair.connect_test.key_name
  iam_instance_profile        = aws_iam_instance_profile.connect_ec2.name
  associate_public_ip_address = true

  root_block_device {
    volume_type = "gp3"
    volume_size = var.node_volume_size_gb
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/user_data/consumer.sh", {
    aws_region                = var.aws_region
    git_repo_url              = var.git_repo_url
    git_token                 = var.git_token
    github_repository         = var.github_repository
    hub_private_ip            = aws_instance.hub.private_ip
    postgres_password         = var.postgres_password
    redis_password            = var.redis_password
    secret_storage_master_key = var.secret_storage_master_key
    sentinel_passphrase       = var.sentinel_passphrase
    ssm_prefix                = var.ssm_prefix
  }))

  tags = { Name = "connect-test-consumer", Role = "consumer" }
}

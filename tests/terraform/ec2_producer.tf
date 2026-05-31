# ── Producer EC2 instance ────────────────────────────────────────────────────
# Runs: sentinel-producer + mock-backend.
# Depends on the hub instance so Terraform has the hub's private IP available
# when rendering the user_data template.

resource "aws_instance" "producer" {
  depends_on = [aws_instance.hub]

  ami                         = data.aws_ssm_parameter.ubuntu_22_04_ami.value
  instance_type               = var.node_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.producer.id]
  key_name                    = aws_key_pair.connect_test.key_name
  iam_instance_profile        = aws_iam_instance_profile.connect_ec2.name
  associate_public_ip_address = true

  root_block_device {
    volume_type = "gp3"
    volume_size = var.node_volume_size_gb
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/user_data/producer.sh", {
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

  tags = { Name = "connect-test-producer", Role = "producer" }
}

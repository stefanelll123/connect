# ── Hub security group ───────────────────────────────────────────────────────
# Accepts service traffic from within the VPC and SSH from the operator CIDR.

resource "aws_security_group" "hub" {
  name        = "connect-test-hub"
  description = "Connect test hub: postgres, redis, hardhat, discovery, governance"
  vpc_id      = aws_vpc.connect_test.id

  # PostgreSQL — accessed by producer and consumer sentinels
  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # Redis — accessed by producer and consumer sentinels
  ingress {
    description = "Redis from VPC"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # Anvil / Hardhat RPC — accessed by sentinels and governance
  ingress {
    description = "Anvil RPC from VPC"
    from_port   = 8545
    to_port     = 8545
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # Discovery service REST API
  ingress {
    description = "Discovery API from VPC"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # Governance service
  ingress {
    description = "Governance API from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # OpenTelemetry Collector — OTLP gRPC + HTTP
  ingress {
    description = "OTLP gRPC from VPC"
    from_port   = 4317
    to_port     = 4318
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # SSH operator access
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "connect-test-hub" }
}

# ── Producer security group ──────────────────────────────────────────────────

resource "aws_security_group" "producer" {
  name        = "connect-test-producer"
  description = "Connect test producer: sentinel-producer + mock-backend"
  vpc_id      = aws_vpc.connect_test.id

  # Sentinel producer — consumer connects here during Phase A / Phase B
  ingress {
    description = "Sentinel producer from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # Mock backend — producer sentinel forwards proxied requests here
  ingress {
    description = "Mock backend from VPC"
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # SSH operator access
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "connect-test-producer" }
}

# ── Consumer security group ──────────────────────────────────────────────────

resource "aws_security_group" "consumer" {
  name        = "connect-test-consumer"
  description = "Connect test consumer: sentinel-consumer + load test runner"
  vpc_id      = aws_vpc.connect_test.id

  # Sentinel consumer API
  ingress {
    description = "Sentinel consumer from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.connect_test.cidr_block]
  }

  # SSH operator access (also used to copy load test results)
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "connect-test-consumer" }
}

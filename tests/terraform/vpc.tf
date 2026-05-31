# ── VPC ─────────────────────────────────────────────────────────────────────

resource "aws_vpc" "connect_test" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "connect-test-vpc" }
}

# Single public subnet — all 3 instances live here.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.connect_test.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = { Name = "connect-test-public" }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.connect_test.id
  tags   = { Name = "connect-test-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.connect_test.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = { Name = "connect-test-rt-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

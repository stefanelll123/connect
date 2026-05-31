# IAM role assumed by all three EC2 instances.
# Grants read/write access to SSM Parameter Store under the /connect-test/ prefix
# so instances can coordinate (hub writes contract addresses; producer/consumer read them).

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "connect_ec2" {
  name               = "connect-test-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  tags               = { Name = "connect-test-ec2-role" }
}

data "aws_iam_policy_document" "ssm_access" {
  statement {
    sid    = "SSMParameterReadWrite"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:PutParameter",
      "ssm:DeleteParameter",
    ]
    resources = [
      "arn:aws:ssm:${var.aws_region}:*:parameter${var.ssm_prefix}/*",
    ]
  }
}

resource "aws_iam_role_policy" "ssm_access" {
  name   = "connect-test-ssm-access"
  role   = aws_iam_role.connect_ec2.id
  policy = data.aws_iam_policy_document.ssm_access.json
}

resource "aws_iam_instance_profile" "connect_ec2" {
  name = "connect-test-ec2-profile"
  role = aws_iam_role.connect_ec2.name
}

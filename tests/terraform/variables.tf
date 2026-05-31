# ── AWS / Infrastructure ────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "hub_instance_type" {
  description = "EC2 instance type for the hub node (discovery + DB + blockchain)."
  type        = string
  default     = "t3.large"
}

variable "node_instance_type" {
  description = "EC2 instance type for producer and consumer nodes."
  type        = string
  default     = "t3.medium"
}

variable "hub_volume_size_gb" {
  description = "Root EBS volume size (GiB) for the hub node."
  type        = number
  default     = 40
}

variable "node_volume_size_gb" {
  description = "Root EBS volume size (GiB) for producer/consumer nodes."
  type        = number
  default     = 24
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key file to upload as an EC2 key pair."
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into all instances. Restrict to your IP."
  type        = string
  default     = "0.0.0.0/0" # Tighten before production use.
}

# ── Source repository ───────────────────────────────────────────────────────

variable "git_repo_url" {
  description = "HTTPS URL of the Connect repository to clone on each instance."
  type        = string
  default     = "https://github.com/your-org/connect.git"
}

variable "git_token" {
  description = "GitHub PAT (or equivalent) for cloning a private repository. Leave empty for public repos."
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_repository" {
  description = "GitHub repository slug (owner/repo) used as the Docker image namespace."
  type        = string
  default     = "local/sentinel"
}

# ── Application secrets ─────────────────────────────────────────────────────

variable "postgres_password" {
  description = "PostgreSQL superuser password (min 16 chars)."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.postgres_password) >= 16
    error_message = "postgres_password must be at least 16 characters."
  }
}

variable "redis_password" {
  description = "Redis password (min 16 chars)."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.redis_password) >= 16
    error_message = "redis_password must be at least 16 characters."
  }
}

variable "secret_storage_master_key" {
  description = "64 hex characters (32 bytes) used as the AES-256-GCM master key for sentinel key storage."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.secret_storage_master_key))
    error_message = "secret_storage_master_key must be exactly 64 hex characters."
  }
}

variable "sentinel_passphrase" {
  description = "Passphrase used to encrypt the sentinel wallet on disk."
  type        = string
  sensitive   = true
  default     = "loadtest-passphrase-change-me"
}

variable "discovery_admin_api_key" {
  description = "Admin API key for the Discovery service."
  type        = string
  sensitive   = true
  default     = "loadtest-admin-key-change-me"
}

variable "hardhat_private_key" {
  description = "Private key of the Anvil deployer account (default: Anvil account #0)."
  type        = string
  sensitive   = true
  default     = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
}

# ── SSM namespace ───────────────────────────────────────────────────────────

variable "ssm_prefix" {
  description = "SSM Parameter Store path prefix used to coordinate between instances."
  type        = string
  default     = "/connect-test"
}

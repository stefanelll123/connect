output "hub_public_ip" {
  description = "Public IP of the hub node (discovery, DB, blockchain)."
  value       = aws_instance.hub.public_ip
}

output "producer_public_ip" {
  description = "Public IP of the producer node (sentinel-producer + mock-backend)."
  value       = aws_instance.producer.public_ip
}

output "consumer_public_ip" {
  description = "Public IP of the consumer node (sentinel-consumer + load test runner)."
  value       = aws_instance.consumer.public_ip
}

output "hub_private_ip" {
  description = "Private IP of the hub — used by producer/consumer for inter-service calls."
  value       = aws_instance.hub.private_ip
}

# ── Ready-made commands ──────────────────────────────────────────────────────

output "ssh_hub" {
  description = "SSH command for the hub node."
  value       = "ssh -i ~/.ssh/id_rsa ubuntu@${aws_instance.hub.public_ip}"
}

output "ssh_producer" {
  description = "SSH command for the producer node."
  value       = "ssh -i ~/.ssh/id_rsa ubuntu@${aws_instance.producer.public_ip}"
}

output "ssh_consumer" {
  description = "SSH command for the consumer node."
  value       = "ssh -i ~/.ssh/id_rsa ubuntu@${aws_instance.consumer.public_ip}"
}

output "discovery_url" {
  description = "Discovery service base URL (public)."
  value       = "http://${aws_instance.hub.public_ip}:8000"
}

output "sentinel_producer_url" {
  description = "Sentinel producer base URL (public)."
  value       = "http://${aws_instance.producer.public_ip}:8080"
}

output "sentinel_consumer_url" {
  description = "Sentinel consumer base URL (public)."
  value       = "http://${aws_instance.consumer.public_ip}:8080"
}

output "load_test_env_snippet" {
  description = "Paste-ready env vars for running load tests from your local machine."
  value       = <<-EOT
    export PRODUCER_URL=http://${aws_instance.producer.public_ip}:8080
    export CONSUMER_URL=http://${aws_instance.consumer.public_ip}:8080
    export DISCOVERY_URL=http://${aws_instance.hub.public_ip}:8000
    export AWS_REGION=${var.aws_region}
    export SSM_PREFIX=${var.ssm_prefix}
  EOT
}

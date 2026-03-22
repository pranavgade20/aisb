locals {
  attack_image_name  = "kali-last-snapshot-amd64-2025.2.0-*"
  attack_image_owner = "679593333241"
  install_ssm_agent_script = base64encode(<<-EOF
    #!/bin/bash
    mkdir /tmp/ssm
    cd /tmp/ssm
    wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb
    sudo dpkg -i amazon-ssm-agent.deb
    sudo start amazon-ssm-agent
  EOF
  )
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "attack_image" {
  most_recent = true
  owners = [local.attack_image_owner]

  filter {
    name = "name"
    values = [local.attack_image_name]
  }
  filter {
    name = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_instance" "attack_target" {
  count                                = var.lab_instances_count
  ami                                  = var.attack_target_ami
  associate_public_ip_address = true # TODO: set to false and move to private subnet; requires SSM VPC endpoint
  iam_instance_profile                 = aws_iam_instance_profile.ssm_profile.name
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.ec2_instance_type
  key_name                             = var.key_pair_name
  vpc_security_group_ids = [
    aws_security_group.all_in_local_network[count.index].id,
    aws_security_group.all_outbound[count.index].id
  ]
  subnet_id = module.vpc[count.index].private_subnets[0]
  user_data = local.install_ssm_agent_script
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    delete_on_termination = true
    encrypted             = false
    volume_size           = 16
    volume_type           = "gp2"
  }
  tags = {
    Name             = "target-host-corrosion2-${count.index}"
    "instance-index" = count.index
  }
}


resource "aws_instance" "attack_host_kali" {
  count                                = var.lab_instances_count
  ami                                  = data.aws_ami.attack_image.id
  associate_public_ip_address          = true
  iam_instance_profile                 = aws_iam_instance_profile.ssm_profile.name
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.ec2_instance_type
  key_name                             = var.key_pair_name
  vpc_security_group_ids = [
    aws_security_group.public_ip_ssh_ingress[count.index].id,
    aws_security_group.all_in_local_network[count.index].id,
    aws_security_group.all_outbound[count.index].id
  ]
  subnet_id = module.vpc[count.index].public_subnets[0]
  user_data = local.install_ssm_agent_script
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    delete_on_termination = true
    encrypted             = false
    volume_size           = 20
    volume_type           = "gp2"
  }
  tags = {
    Name             = "attack-host-kali-${count.index}"
    "instance-index" = count.index
  }
}

###
# Outputs
###
output "instance_url" {
  value = [
    for i in aws_instance.attack_host_kali :
    "https://${var.aws_region}.console.aws.amazon.com/ec2/home?region=${var.aws_region}#InstanceDetails:instanceId=${i.id})"
  ]
}

output "ssh_connect_command" {
  value = [
    for i in aws_instance.attack_host_kali :
    "ssh kali@${i.public_dns}"
  ]
}

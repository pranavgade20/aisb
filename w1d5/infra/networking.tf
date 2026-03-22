locals {
  vpc_cidr               = "172.16.0.0/16"
  vpc_availability_zones = data.aws_availability_zones.available.names
}

module "vpc" {
  count   = var.lab_instances_count
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.4.0"

  name            = "lab-vpc-${count.index}"
  cidr            = local.vpc_cidr
  azs             = local.vpc_availability_zones
  private_subnets = [for k, v in local.vpc_availability_zones : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.vpc_availability_zones : cidrsubnet(local.vpc_cidr, 8, k + 48)]

  enable_nat_gateway            = false
  single_nat_gateway            = true
  manage_default_network_acl    = false
  manage_default_route_table    = false
  manage_default_security_group = false
  tags = {
    "instance-index" = count.index
  }
}

resource "aws_security_group" "public_ip_ssh_ingress" {
  count       = var.lab_instances_count
  description = "ssh ingress from anywhere (${count.index})"
  vpc_id      = module.vpc[count.index].vpc_id
  name        = "allow_ssh_from_anywhere-${count.index}"

  ingress = [
    {
      description = "SSH"
      cidr_blocks = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      prefix_list_ids = []
      security_groups = []
      self        = false
    }
  ]
  tags = {
    "instance-index" = count.index
  }
}

resource "aws_security_group" "all_in_local_network" {
  count = var.lab_instances_count
  description = "All in local network (${count.index})"
  name        = "all-in-local-network-${count.index}"
  vpc_id      = module.vpc[count.index].vpc_id
  egress = [
    {
      cidr_blocks = []
      description = "Allow all traffic within this security group"
      from_port   = 0
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      protocol    = "-1"
      security_groups = []
      self        = true
      to_port     = 0
    }
  ]
  ingress = [
    {
      cidr_blocks = []
      description = "Allow all traffic within this security group"
      from_port   = 0
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      protocol    = "-1"
      security_groups = []
      self        = true
      to_port     = 0
    }
  ]
  tags = {
    "instance-index" = count.index
  }
}

resource "aws_security_group" "all_outbound" {
  count       = var.lab_instances_count
  description = "Allow all outbound traffic (${count.index})"
  name        = "all-outbound-${count.index}"
  vpc_id      = module.vpc[count.index].vpc_id
  
  egress = [
    {
      cidr_blocks      = ["0.0.0.0/0"]
      description      = "Allow all outbound traffic"
      from_port        = 0
      ipv6_cidr_blocks = ["::/0"]
      prefix_list_ids  = []
      protocol         = "-1"
      security_groups  = []
      self             = false
      to_port          = 0
    }
  ]
  
  tags = {
    "instance-index" = count.index
  }
}


variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "lab_instances_count" {
  type    = number
  default = 1
}

variable "ec2_instance_type" {
  type    = string
  default = "t2.medium"
}

variable "key_pair_name" {
  type    = string
  default = null
}

variable "availability_zone_index" {
  type    = number
  default = 0
}

variable "attack_target_ami" {
  type    = string
  default = "ami-069fccac60fb3e8ad" # corrosion2-v4
}
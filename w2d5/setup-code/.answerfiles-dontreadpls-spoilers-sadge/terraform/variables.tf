variable "region" {
  default = "us-east1"
}

variable "zone" {
  default = "b"
}

variable "project_id" {}

variable "project_number" {}

# Flag configuration for module gating
variable "flag1_module2_key" {
  description = "Flag value to unlock Module 2 (System Status). This flag is found in the dev bucket during Module 1."
  type        = string
  default     = "flag{found-the-lazy-dev}"
}

variable "flag2_module3_key" {
  description = "Flag value to unlock Module 3 (Monitoring). This flag is found in the terraform state file during Module 2."
  type        = string
  default     = "flag{found-the-secret-infrastructure}"
}

variable "flag3_module4_key" {
  description = "Flag value to unlock Module 4 (Admin). This flag is found in the terraform state file during Module 3."
  type        = string
  default     = "flag{youre_in_now_escalate}"
}


variable "flag4_solve_module4" {
  description = "Flag value to solve Module 4 (Admin). This flag is found in the GPT-6."
  type        = string
  default     = "flag{final_challenge_find_gpt6}"
}

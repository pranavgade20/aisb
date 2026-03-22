#!/usr/bin/env bash

usage() { echo "Usage: $0 [--skip-init]" ; exit 1; }

SKIP_INIT=
if [[ "$1" == "--skip-init" ]]; then
  SKIP_INIT=true
elif [[ -n "$1" ]]; then
  usage
fi

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

if [[ -z "${SKIP_INIT}" ]]; then
  terraform init -upgrade -reconfigure
fi
terraform apply -var-file="terraform.tfvars"
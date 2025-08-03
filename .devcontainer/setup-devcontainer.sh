#!/usr/bin/env bash

pip3 install --user -r requirements.txt

git config pull.rebase true
git config --type bool push.autoSetupRemote true

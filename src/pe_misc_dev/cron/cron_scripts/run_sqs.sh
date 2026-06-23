#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate pe-reports &&
# pyenv activate pe-reports &&

cd /var/www/SQS_test || exit

python3 run_sqs_scans_pe.py

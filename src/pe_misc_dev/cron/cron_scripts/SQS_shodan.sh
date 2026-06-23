#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate pe-reports &&

cd /var/www/SQS_pe || exit

python3 pe_sqs.py --scans=shodan --orgs_file=pe_report_on_orgs.json

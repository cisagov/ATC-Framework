#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate pe-reports &&
# pyenv activate pe-reports &&

cd /var/www/pe-reports/src/adhoc || exit

python3 hibp_latest_rev.py &&

echo "HIBP Script is done"

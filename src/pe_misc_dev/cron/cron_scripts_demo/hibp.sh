#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate pe-reports &&
# pyenv activate pe-reports &&

cd /var/www/pe-reports || exit

python3 src/adhoc/hibp_latest.py

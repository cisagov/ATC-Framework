#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate pe-reports &&

cd /var/www/threathunt_scans || exit

python3 threathunt_run_scans.py

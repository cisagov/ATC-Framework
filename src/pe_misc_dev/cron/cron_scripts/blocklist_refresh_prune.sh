#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate atc-framework &&

cd /var/www/ATC-Framework/src/pe_source || exit

python3 blocklist_de.py prune

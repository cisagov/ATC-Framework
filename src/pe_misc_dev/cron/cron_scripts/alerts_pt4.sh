#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate atc-framework &&

cd /var/www/ATC-Framework || exit

pe-source cybersixgill --cybersix-methods=alerts --soc_med_included --orgs=

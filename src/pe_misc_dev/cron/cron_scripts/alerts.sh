#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate atc-framework &&

cd /var/www/ATC-Framework || exit

echo "Script ran at $(date)" >> /var/www/ATC-Framework/cronOutput.log &&

pe-source cybersixgill --cybersix-methods=alerts --soc_med_included &&

echo "Finished run at $(date)" >> /var/www/ATC-Framework/cronOutpout.log

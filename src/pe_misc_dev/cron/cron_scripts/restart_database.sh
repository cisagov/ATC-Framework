#!/bin/bash
export PATH=~/.pyenv/shims:~/.pyenv/bin:"$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv activate atc-framework &&

sudo systemctl stop celeryDjango.service
sleep 30s
sudo systemctl start celeryDjango.service
sleep 30s
sudo systemctl restart pe-reportsDjango.service

# !/bin/bash

# pyenv install 3.7.9
# pyenv local 3.7.9
virtualenv .venv -p python3.7.9
source .venv/bin/activate
pip install -r requirements.txt
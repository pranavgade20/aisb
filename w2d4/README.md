# W2D4

## Introduction
Your AI company hired external contracting to migrate their gift card system. Unfortunately it seems the contractors haven't done a great job. You are assigned to review the code. If you do not make the necessary changes your company may suffer significant losses.

## Setup

### Switch to pyenv
``` bash
brew install pyenv
# add pyenv to path
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init -)"' >> ~/.zshrc

pyenv install 3.11.9
pyenv local 3.11.9
python --version
```

``` bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Migration
1. Create appropriate `.gitignore` for Python/Django projects
2. Setup Django:
``` bash
python3 manage.py makemigrations LegacySite
python3 manage.py migrate
python3 manage.py shell -c 'import import_dbs'
```
3. Generate fixtures:
``` bash
mkdir -p LegacySite/fixtures
python3 manage.py dumpdata LegacySite --indent=4 > LegacySite/fixtures/testdata.json
```
4. Run the server:
``` bash
python3 manage.py runserver
```
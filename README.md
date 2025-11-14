# BeeLogin

Exploring authentication.

## Run

```sh
# tested with Python 3.14
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

fastapi dev beelogin/main.py
```


## Notes

https://pyauth.github.io/pyotp/

## TODO

- redirect URI whitelist
- users whitelist
    - possibly with admin/non-admin separation
    - store in TOML
- persistence
    - session_ids

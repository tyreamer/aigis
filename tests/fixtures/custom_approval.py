"""Fixture: various custom approval wrapper patterns."""
from langchain.tools import tool


# --- Pattern 1: class-based approval decorator ---
class PolicyGate:
    def __init__(self, level="standard"):
        self.level = level

    def __call__(self, fn):
        def wrapper(*args, **kwargs):
            print(f"Policy check (level={self.level}) for {fn.__name__}")
            return fn(*args, **kwargs)
        return wrapper


@tool
@PolicyGate(level="elevated")
def deploy_service(env: str):
    """Deploy with class-based policy gate."""
    import subprocess
    subprocess.run(["deploy", "--env", env])


# --- Pattern 2: approval call in body ---
@tool
def manual_confirm_delete(path: str):
    """Approval via input() call in body."""
    confirm = input(f"Really delete {path}? [y/n] ")
    if confirm.lower() == "y":
        import os
        os.remove(path)


# --- Pattern 3: function with 'authorize' in name ---
def authorize_action(action_name):
    """Custom authorization function."""
    return True


@tool
def guarded_http_post(url: str, data: str):
    """Calls authorize_action before posting."""
    authorize_action("http_post")
    import requests
    requests.post(url, json={"data": data})


# --- Pattern 4: no approval at all ---
@tool
def unguarded_write(path: str, content: str):
    """Writes to file with no approval."""
    with open(path, "w") as f:
        f.write(content)

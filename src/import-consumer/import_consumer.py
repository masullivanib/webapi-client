from datetime import datetime
from pathlib import Path
import inspect, sys
import json

# Directory structure
WEBAPI_ROOT = "~/IBKR/webapi"
CONSUMERS_ROOT = f"{WEBAPI_ROOT}/consumers"
WEBAPI_LOGS_ROOT = f"{WEBAPI_ROOT}/webapi-client-logs"

# Filename patterns
PEM_PATHS_JSON_PTN = "{consumer}_pem_paths.json"
AUTH_JSON_PTN = "{consumer}-{user}_auth.json"
SESSION_JSON_PTN = "{consumer}-{user}_session.json"
LOG_PTN = "{timestamp}_{consumer}-{user}.log"


def get_id_and_session_args(consumer: str, user: str) -> dict:
    consumers_root = Path(CONSUMERS_ROOT).expanduser()
    webapi_logs_root = Path(WEBAPI_LOGS_ROOT).expanduser()
    consumer_dir = consumers_root.joinpath(consumer)

    try:
        pems_path = consumer_dir.joinpath(
            PEM_PATHS_JSON_PTN.format(consumer=consumer)
        ).resolve(True)
        auth_path = consumer_dir.joinpath(
            AUTH_JSON_PTN.format(consumer=consumer, user=user)
        ).resolve(True)
        sesh_path = consumer_dir.joinpath(
            SESSION_JSON_PTN.format(consumer=consumer, user=user)
        ).resolve(True)
        log_path = webapi_logs_root.joinpath(
            LOG_PTN.format(
                timestamp=datetime.now().strftime("%Y-%m-%d"),
                consumer=consumer,
                user=user,
            )
        ).resolve(False)
    except (OSError, ValueError) as e:
        print(f"{e}\n[ERROR] Cannot access JSON configs. Exiting...")
        raise SystemExit(0)

    arg_dict = {
        "consumer_key": consumer,
        "session_cache_path": sesh_path,
        "log_path": log_path,
    }

    try:
        for k, v in json.loads(pems_path.read_text()).items():
            arg_dict[k] = consumer_dir.joinpath(v).resolve(True).read_bytes()
        arg_dict.update(json.loads(auth_path.read_text()))
        assert all(bool(str(v)) for v in arg_dict.values())
    except (OSError, ValueError) as e:
        print(f"{e}\n[ERROR] Cannot read from PEM files. Exiting...")
        raise SystemExit(0)
    except AssertionError as e:
        print(f"{e}\n[ERROR] Ensure all identity values are nonempty.\nExiting...")
        raise SystemExit(0)
    try:
        arg_dict.update(json.loads(sesh_path.read_text()))
    except FileNotFoundError:
        sesh_path.touch(exist_ok=True)
    log_path.touch(exist_ok=True)
    with log_path.open("a+") as f:
        f.write(
            f"\n\n{'~'*5} {{}} {{}}\n".format(
                datetime.now().strftime("%H:%M:%S"),
                inspect.getframeinfo(sys._getframe(1)).filename,
            )
        )
    return arg_dict


def simple_auth(consumer: str, user: str) -> dict:
    consumers_root = Path(CONSUMERS_ROOT).expanduser()
    webapi_logs_root = Path(WEBAPI_LOGS_ROOT).expanduser()
    consumer_dir = consumers_root.joinpath(consumer)

    try:
        auth_path = consumer_dir.joinpath(
            AUTH_JSON_PTN.format(consumer=consumer, user=user)
        ).resolve(True)
        sesh_path = consumer_dir.joinpath(
            SESSION_JSON_PTN.format(consumer=consumer, user=user)
        ).resolve(True)
        log_path = webapi_logs_root.joinpath(
            LOG_PTN.format(
                timestamp=datetime.now().strftime("%Y-%m-%d"),
                consumer=consumer,
                user=user,
            )
        ).resolve(False)
    except (OSError, ValueError) as e:
        print(f"{e}\n[ERROR] Cannot access JSON configs. Exiting...")
        raise SystemExit(0)

    arg_dict = {
        "consumer_key": consumer,
        "session_cache_path": sesh_path,
        "log_path": log_path,
        "encryption_key": None,
        "signature_key": None,
        "dhparam": None,
        "access_token_secret": None,
    }

    try:
        arg_dict.update(json.loads(auth_path.read_text()))
    except (OSError, ValueError) as e:
        print(f"{e}\n[ERROR] Cannot read from PEM files. Exiting...")
        raise SystemExit(0)
    try:
        arg_dict.update(json.loads(sesh_path.read_text()))
    except FileNotFoundError:
        sesh_path.touch(exist_ok=True)
    log_path.touch(exist_ok=True)
    with log_path.open("a+") as f:
        f.write(
            f"\n\n{'~'*5} {{}} {{}}\n".format(
                datetime.now().strftime("%H:%M:%S"),
                inspect.getframeinfo(sys._getframe(1)).filename,
            )
        )
    return arg_dict

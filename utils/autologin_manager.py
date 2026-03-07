import importlib
import os
import threading
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse

import requests

from utils.logging import get_logger

logger = get_logger(__name__)


class AutologinError(Exception):
    pass


class BrokerAutologinProvider(ABC):
    name: str
    callback_token_key: str

    @property
    @abstractmethod
    def required_env_vars(self) -> list[str]:
        pass

    @abstractmethod
    def get_callback_token(self) -> str:
        pass


def _get_provider_for_broker(broker_name: str) -> BrokerAutologinProvider | None:
    try:
        module = importlib.import_module(f"broker.{broker_name}.autologin")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BrokerAutologinProvider) and attr is not BrokerAutologinProvider:
                return attr()
    except Exception as e:
        logger.error(f"Error loading autologin provider for {broker_name}: {e}")
    return None


def _as_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise AutologinError(f"Missing required env var: {name}")
    return value


def _get_configured_broker() -> str:
    configured = os.getenv("OPENALGO_AUTOLOGIN_BROKER", "").strip().lower()
    if configured:
        return configured

    redirect_url = os.getenv("REDIRECT_URL", "")
    parsed = urlparse(redirect_url)
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) >= 2 and path_parts[-1] == "callback":
        return path_parts[-2].lower()

    return "zerodha"


def _wait_for_openalgo(base_url: str, retries: int, delay_seconds: int) -> None:
    endpoint = f"{base_url}/auth/check-setup"
    last_error = None
    for _ in range(max(1, retries)):
        try:
            response = requests.get(endpoint, timeout=5)
            if response.status_code == 200:
                return
            last_error = f"status={response.status_code}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(max(1, delay_seconds))
    raise AutologinError(f"OpenAlgo not ready: {last_error}")


def _openalgo_login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    csrf_res = session.get(f"{base_url}/auth/csrf-token", timeout=5)
    if csrf_res.status_code == 200:
        data = csrf_res.json()
        if "csrf_token" in data:
            session.headers.update({"X-CSRFToken": data["csrf_token"]})
            
    response = session.post(
        f"{base_url}/auth/login",
        data={"username": username, "password": password},
        timeout=10,
    )

    if response.status_code != 200:
        raise AutologinError(f"OpenAlgo login failed with status {response.status_code}")

    payload = {}
    try:
        payload = response.json()
    except Exception:
        payload = {}

    if payload.get("status") != "success":
        raise AutologinError(f"OpenAlgo login failed: {payload.get('message', 'unknown error')}")


def _attach_provider_to_openalgo_session(
    session: requests.Session,
    base_url: str,
    provider: BrokerAutologinProvider,
    callback_token: str,
) -> None:
    callback_url = f"{base_url}/{provider.name}/callback"
    response = session.get(
        callback_url,
        params={provider.callback_token_key: callback_token},
        allow_redirects=True,
        timeout=20,
    )

    if response.status_code != 200:
        raise AutologinError(f"{provider.name} callback failed with status {response.status_code}")


def _autologin_worker() -> None:
    host = os.getenv("FLASK_HOST_IP", "127.0.0.1")
    port = _as_int("FLASK_PORT", 5000)
    base_url = f"http://{host}:{port}"

    startup_delay = _as_int("OPENALGO_AUTOLOGIN_STARTUP_DELAY_SECONDS", 3)
    retries = _as_int("OPENALGO_AUTOLOGIN_RETRIES", 5)
    retry_delay = _as_int("OPENALGO_AUTOLOGIN_RETRY_DELAY_SECONDS", 2)

    if startup_delay > 0:
        time.sleep(startup_delay)

    try:
        _wait_for_openalgo(base_url, retries=retries, delay_seconds=retry_delay)

        broker_name = _get_configured_broker()
        provider = _get_provider_for_broker(broker_name)
        if provider is None:
            raise AutologinError(
                f"No autologin provider found for broker: {broker_name}. "
                f"Ensure broker/{broker_name}/autologin.py exists."
            )

        oa_user = require_env("OPENALGO_USERNAME")
        oa_pass = require_env("OPENALGO_PASSWORD")
        for env_name in provider.required_env_vars:
            require_env(env_name)

        session = requests.Session()

        logger.info("[Autologin] Starting OpenAlgo login")
        _openalgo_login(session, base_url, oa_user, oa_pass)

        logger.info("[Autologin] Starting %s backend authentication", provider.name)
        callback_token = provider.get_callback_token()

        _attach_provider_to_openalgo_session(session, base_url, provider, callback_token)
        logger.info("[Autologin] %s authentication completed", provider.name)

    except Exception as exc:
        logger.error(f"[Autologin] Failed: {exc}")
        raise  # Re-raise so sync caller knows it failed


def trigger_autologin_sync() -> bool:
    """
    Synchronously run the autologin flow.
    Call this when a token expires (401/403) to instantly recover auth.
    """
    if os.getenv("OPENALGO_AUTOLOGIN", "false").lower() != "true":
        return False
        
    logger.info("[Autologin] Sync autologin triggered")
    try:
        # Save original startup delay and bypass it for sync triggers
        original_delay = os.environ.get("OPENALGO_AUTOLOGIN_STARTUP_DELAY_SECONDS")
        os.environ["OPENALGO_AUTOLOGIN_STARTUP_DELAY_SECONDS"] = "0"
        
        _autologin_worker()
        
        # Restore environment
        if original_delay is not None:
            os.environ["OPENALGO_AUTOLOGIN_STARTUP_DELAY_SECONDS"] = original_delay
        else:
            del os.environ["OPENALGO_AUTOLOGIN_STARTUP_DELAY_SECONDS"]
            
        return True
    except Exception as e:
        logger.error(f"[Autologin] Sync trigger failed: {e}")
        return False


def start_autologin() -> None:
    if os.getenv("OPENALGO_AUTOLOGIN", "false").lower() != "true":
        return

    thread = threading.Thread(target=_autologin_worker, daemon=True, name="openalgo-autologin")
    thread.start()
    logger.info("[Autologin] Worker started")

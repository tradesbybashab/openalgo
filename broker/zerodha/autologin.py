import os
from urllib.parse import parse_qs, urlparse

import pyotp
import requests

from utils.autologin_manager import BrokerAutologinProvider, AutologinError, require_env

class ZerodhaAutologinProvider(BrokerAutologinProvider):
    name = "zerodha"
    callback_token_key = "request_token"

    @property
    def required_env_vars(self) -> list[str]:
        return [
            "BROKER_API_KEY",
            "BROKER_USER_ID",
            "BROKER_PASSWORD",
            "BROKER_TOTP_KEY",
        ]

    def get_callback_token(self) -> str:
        api_key = require_env("BROKER_API_KEY")
        user_id = require_env("BROKER_USER_ID")
        password = require_env("BROKER_PASSWORD")
        totp_key = require_env("BROKER_TOTP_KEY")

        kite_session = requests.Session()
        kite_session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            }
        )

        login_resp = kite_session.post(
            "https://kite.zerodha.com/api/login",
            data={"user_id": user_id, "password": password},
            timeout=15,
        )
        login_data = login_resp.json()
        if login_resp.status_code != 200 or login_data.get("status") != "success":
            raise AutologinError(f"Zerodha login step failed: {login_data}")

        request_id = login_data["data"]["request_id"]
        totp_code = pyotp.TOTP(totp_key).now()

        twofa_resp = kite_session.post(
            "https://kite.zerodha.com/api/twofa",
            data={"request_id": request_id, "twofa_value": totp_code, "user_id": user_id},
            timeout=15,
        )
        twofa_data = twofa_resp.json()
        if twofa_resp.status_code != 200 or twofa_data.get("status") != "success":
            raise AutologinError(f"Zerodha TOTP step failed: {twofa_data}")

        # Construct Kite Connect login URL directly (removes dependency on unofficial kiteconnect library)
        auth_url = f"https://kite.zerodha.com/connect/login?v=3&api_key={api_key}"

        redirect_url = None
        try:
            # We don't want to follow the redirect back to our local OpenAlgo instance 
            # because kite_session lacks the OpenAlgo browser cookies and would get kicked to /login.
            response = kite_session.get(auth_url, allow_redirects=False, timeout=10)
            
            redirect_url = response.headers.get("Location")
            if not redirect_url and response.status_code == 200:
                # In some cases with Kite, if allow_redirects is false it might give a 200 with meta refresh
                # or require following. If we follow, we just need to intercept before hitting 127.0.0.1
                pass
                
        except requests.exceptions.ConnectionError:
            pass

        # Safest way: allow redirects but just search history/url for request_token
        if not redirect_url or "request_token" not in redirect_url:
            response = kite_session.get(auth_url, allow_redirects=True, timeout=10)
            
            # Check the final URL first
            urls_to_check = [response.url]
            # Check all history URLs (in case we were redirected to /login at the end)
            urls_to_check.extend([resp.url for resp in response.history])
            
            for u in urls_to_check:
                if "request_token=" in u:
                    redirect_url = u
                    break
            else:
                redirect_url = response.url

        if not redirect_url:
            raise AutologinError("Zerodha redirect URL missing")

        parsed = urlparse(redirect_url)
        request_token = parse_qs(parsed.query).get("request_token", [None])[0]
        if not request_token:
            raise AutologinError(f"request_token not found in Zerodha redirect URL. URL was: {redirect_url}")

        return request_token

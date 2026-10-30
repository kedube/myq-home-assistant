from typing import Final, TypedDict

import probatio as vol
from homeassistant.helpers import selector

from .const import CONF_MFA_METHOD, DEFAULT_MFA_METHOD, MFA_METHOD_EMAIL, MFA_METHOD_SMS


class CredentialsInput(TypedDict):
    email: str
    mfa_method: str
    password: str


class PasswordInput(TypedDict):
    mfa_method: str
    password: str


class BrowserStartInput(TypedDict):
    email: str


class MfaInput(TypedDict):
    code: str


class BrowserCallbackInput(TypedDict):
    callback_url: str


EMAIL_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(
        type=selector.TextSelectorType.EMAIL,
        autocomplete="email",
    )
)
PASSWORD_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(
        type=selector.TextSelectorType.PASSWORD,
        autocomplete="current-password",
    )
)
MFA_SELECTOR = selector.TextSelector(selector.TextSelectorConfig(autocomplete="one-time-code"))
MFA_METHOD_SELECTOR = selector.SelectSelector(
    selector.SelectSelectorConfig(
        options=[MFA_METHOD_EMAIL, MFA_METHOD_SMS],
        translation_key="mfa_method",
    )
)

CREDENTIALS_SCHEMA = vol.Schema(
    {
        vol.Required("email"): EMAIL_SELECTOR,
        vol.Required("password"): PASSWORD_SELECTOR,
        vol.Required(CONF_MFA_METHOD, default=DEFAULT_MFA_METHOD): MFA_METHOD_SELECTOR,
    }
)
BROWSER_START_SCHEMA = vol.Schema({vol.Required("email"): EMAIL_SELECTOR})
REAUTH_SCHEMA = vol.Schema(
    {
        vol.Required("password"): PASSWORD_SELECTOR,
        vol.Required(CONF_MFA_METHOD, default=DEFAULT_MFA_METHOD): MFA_METHOD_SELECTOR,
    }
)
USER_MENU_OPTIONS: Final = ("credentials", "browser_start")
REAUTH_MENU_OPTIONS: Final = ("reauth_credentials", "browser_start")
MFA_SCHEMA = vol.Schema({vol.Required("code"): MFA_SELECTOR})
BROWSER_CALLBACK_SCHEMA = vol.Schema(
    {
        vol.Required("callback_url"): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
        )
    }
)

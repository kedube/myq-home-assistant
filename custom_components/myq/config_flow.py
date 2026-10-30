from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

import probatio as vol
from aiohttp import ClientError, ClientSession, CookieJar
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers.aiohttp_client import (
    async_create_clientsession,
    async_get_clientsession,
)

from .auth import MyQLoginSession
from .client import MyQClient
from .config_flow_forms import (
    BROWSER_CALLBACK_SCHEMA,
    BROWSER_START_SCHEMA,
    CREDENTIALS_SCHEMA,
    MFA_SCHEMA,
    REAUTH_MENU_OPTIONS,
    REAUTH_SCHEMA,
    USER_MENU_OPTIONS,
    BrowserCallbackInput,
    BrowserStartInput,
    CredentialsInput,
    MfaInput,
    PasswordInput,
)
from .const import (
    CONF_EMAIL,
    CONF_MFA_METHOD,
    DEFAULT_MFA_METHOD,
    DOMAIN,
)
from .exceptions import (
    MyQAuthenticationError,
    MyQBrowserSessionExpiredError,
    MyQCloudflareChallengeError,
    MyQError,
    MyQInvalidCallbackError,
    MyQInvalidCredentialsError,
    MyQInvalidMfaError,
    MyQUnsupportedAuthPageError,
)
from .models import OAuthTokens
from .oauth import MyQAuth
from .runtime import MyQConfigData, MyQConfigEntry, tokens_to_data

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LoginAttempt:
    tokens: OAuthTokens | None = None
    error: str | None = None
    browser_url: str | None = None


class MyQConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._email: str | None = None
        self._mfa_method: str | None = None
        self._browser_url: str | None = None
        self._login: MyQLoginSession | None = None
        self._login_session: ClientSession | None = None
        self._reauth_entry: MyQConfigEntry | None = None

    async def async_step_user(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        del user_input
        return self.async_show_menu(
            step_id="user",
            menu_options=USER_MENU_OPTIONS,
        )

    async def async_step_credentials(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        if user_input is not None:
            credentials = cast(CredentialsInput, user_input)
            self._email = credentials["email"].strip().casefold()
            self._async_abort_entries_match({CONF_EMAIL: self._email})
        return await self._async_credentials_step(
            user_input,
            step_id="credentials",
            schema=CREDENTIALS_SCHEMA,
            mfa_step_id="mfa",
        )

    async def async_step_browser_start(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        if self._reauth_entry is not None:
            self._begin_browser_login()
            return await self.async_step_browser()

        if user_input is not None:
            browser_input = cast(BrowserStartInput, user_input)
            self._email = browser_input[CONF_EMAIL].strip().casefold()
            self._mfa_method = DEFAULT_MFA_METHOD
            self._async_abort_entries_match({CONF_EMAIL: self._email})
            self._begin_browser_login()
            return await self.async_step_browser()

        return self.async_show_form(
            step_id="browser_start",
            data_schema=BROWSER_START_SCHEMA,
        )

    async def async_step_mfa(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        return await self._async_mfa_step("mfa", user_input)

    async def async_step_reauth(
        self,
        entry_data: Mapping[str, object],
    ) -> ConfigFlowResult:
        del entry_data
        self._reauth_entry = cast(MyQConfigEntry, self._get_reauth_entry())
        data = cast(MyQConfigData, self._reauth_entry.data)
        self._email = data[CONF_EMAIL]
        self._mfa_method = data[CONF_MFA_METHOD]
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        del user_input
        return self.async_show_menu(
            step_id="reauth_confirm",
            menu_options=REAUTH_MENU_OPTIONS,
            description_placeholders={"email": self._required_email()},
        )

    async def async_step_reauth_credentials(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        return await self._async_credentials_step(
            user_input,
            step_id="reauth_credentials",
            schema=REAUTH_SCHEMA,
            mfa_step_id="reauth_mfa",
            description_placeholders={"email": self._required_email()},
        )

    async def async_step_reauth_mfa(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        return await self._async_mfa_step("reauth_mfa", user_input)

    async def async_step_browser(
        self,
        user_input: dict[str, object] | None = None,
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            callback_input = cast(BrowserCallbackInput, user_input)
            attempt = await self._async_complete_browser(callback_input["callback_url"].strip())
            if attempt.tokens is not None:
                return await self._async_finish(attempt.tokens)
            errors["base"] = attempt.error or "unknown"

        return self.async_show_form(
            step_id="browser",
            data_schema=BROWSER_CALLBACK_SCHEMA,
            errors=errors,
            description_placeholders={
                "authorization_url": self._required_browser_url(),
                "email": self._required_email(),
            },
        )

    async def _async_credentials_step(
        self,
        user_input: dict[str, object] | None,
        *,
        step_id: str,
        schema: vol.Schema,
        mfa_step_id: str,
        description_placeholders: dict[str, str] | None = None,
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            password_input = cast(PasswordInput, user_input)
            self._mfa_method = password_input[CONF_MFA_METHOD]
            attempt = await self._async_start_login(password_input["password"])
            if attempt.tokens is not None:
                return await self._async_finish(attempt.tokens)
            if attempt.browser_url is not None:
                return await self.async_step_browser()
            if attempt.error is None:
                return await self._async_mfa_step(mfa_step_id, None)
            errors["base"] = attempt.error

        return self.async_show_form(
            step_id=step_id,
            data_schema=schema,
            errors=errors,
            description_placeholders=description_placeholders,
        )

    async def _async_mfa_step(
        self,
        step_id: str,
        user_input: dict[str, object] | None,
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            mfa_input = cast(MfaInput, user_input)
            code = mfa_input["code"].strip()
            if not re.fullmatch(r"\d{6}", code):
                errors["base"] = "invalid_mfa"
            else:
                attempt = await self._async_submit_mfa(code)
                if attempt.tokens is not None:
                    return await self._async_finish(attempt.tokens)
                if attempt.browser_url is not None:
                    return await self.async_step_browser()
                errors["base"] = attempt.error or "unknown"

        return self.async_show_form(
            step_id=step_id,
            data_schema=MFA_SCHEMA,
            errors=errors,
        )

    async def _async_start_login(self, password: str) -> LoginAttempt:
        self._create_login_session()
        try:
            tokens = await self._required_login().async_start(
                self._required_email(),
                password,
                self._required_mfa_method(),
            )
        except MyQInvalidCredentialsError:
            self._close_login()
            return LoginAttempt(error="invalid_auth")
        except (MyQCloudflareChallengeError, MyQUnsupportedAuthPageError) as error:
            return self._browser_fallback(error, step="login")
        except ClientError:
            self._close_login()
            return LoginAttempt(error="cannot_connect")
        except MyQError:
            _LOGGER.exception("Unexpected MyQ error while starting authentication")
            self._close_login()
            return LoginAttempt(error="unknown")
        return LoginAttempt(tokens=tokens)

    async def _async_complete_browser(self, callback_url: str) -> LoginAttempt:
        if self._login is None:
            return LoginAttempt(error="authentication_expired")
        try:
            tokens = await self._required_login().async_complete_browser(callback_url)
        except MyQInvalidCallbackError:
            return LoginAttempt(error="invalid_callback")
        except MyQBrowserSessionExpiredError:
            return self._restart_browser("browser_session_expired")
        except MyQAuthenticationError:
            return self._restart_browser("browser_auth_failed")
        except ClientError:
            return self._restart_browser("cannot_connect")
        except MyQError:
            _LOGGER.exception("Unexpected MyQ error while completing browser authentication")
            return self._restart_browser("unknown")
        return LoginAttempt(tokens=tokens)

    async def _async_submit_mfa(self, code: str) -> LoginAttempt:
        if self._login is None:
            return LoginAttempt(error="authentication_expired")
        try:
            tokens = await self._required_login().async_submit_mfa(code)
        except MyQInvalidMfaError:
            return LoginAttempt(error="invalid_mfa")
        except (MyQCloudflareChallengeError, MyQUnsupportedAuthPageError) as error:
            return self._browser_fallback(error, step="MFA verification")
        except ClientError:
            return LoginAttempt(error="cannot_connect")
        except MyQError:
            _LOGGER.exception("Unexpected MyQ error while submitting MFA")
            self._close_login()
            return LoginAttempt(error="unknown")
        return LoginAttempt(tokens=tokens)

    async def _async_finish(self, tokens: OAuthTokens) -> ConfigFlowResult:
        email_address = self._required_email()
        auth = MyQAuth(async_get_clientsession(self.hass), tokens, lambda _: None)
        client = MyQClient(async_get_clientsession(self.hass), auth)
        try:
            doors = await client.async_get_garage_doors()
        except ClientError:
            self._close_login()
            return self.async_abort(reason="cannot_connect")
        except MyQError:
            _LOGGER.exception("Unexpected MyQ API error during account validation")
            self._close_login()
            return self.async_abort(reason="unknown")
        self._close_login()
        if not doors:
            return self.async_abort(reason="no_devices")

        data = MyQConfigData(
            email=email_address,
            mfa_method=self._required_mfa_method(),
            tokens=tokens_to_data(tokens),
        )
        if self._reauth_entry is not None:
            await self.async_set_unique_id(email_address)
            self._abort_if_unique_id_mismatch()
            return self.async_update_reload_and_abort(
                self._reauth_entry,
                data=data,
            )

        await self.async_set_unique_id(email_address)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=email_address, data=data)

    def _close_login(self) -> None:
        if self._login_session is not None:
            self._login_session.detach()
        self._login_session = None
        self._login = None
        self._browser_url = None

    def _create_login_session(self) -> None:
        self._close_login()
        session = async_create_clientsession(
            self.hass,
            auto_cleanup=False,
            cookie_jar=CookieJar(),
        )
        self._login_session = session
        self._login = MyQLoginSession(session)

    def _begin_browser_login(self) -> None:
        self._create_login_session()
        self._start_browser()

    def _start_browser(self) -> str:
        self._browser_url = self._required_login().start_browser()
        return self._browser_url

    def _browser_fallback(
        self,
        error: MyQCloudflareChallengeError | MyQUnsupportedAuthPageError,
        *,
        step: str,
    ) -> LoginAttempt:
        reason = f"{type(error).__name__}: {error}".rstrip(": ")
        _LOGGER.warning(
            "Automatic MyQ authentication could not continue during %s; "
            "offering browser sign-in: %s",
            step,
            reason,
        )
        return LoginAttempt(browser_url=self._start_browser())

    def _restart_browser(self, error: str) -> LoginAttempt:
        self._start_browser()
        return LoginAttempt(error=error)

    def _required_browser_url(self) -> str:
        if self._browser_url is None:
            raise RuntimeError("The MyQ config flow has no browser authorization URL")
        return self._browser_url

    def _required_email(self) -> str:
        if self._email is None:
            raise RuntimeError("The MyQ config flow has no email address")
        return self._email

    def _required_mfa_method(self) -> str:
        if self._mfa_method is None:
            raise RuntimeError("The MyQ config flow has no MFA method")
        return self._mfa_method

    def _required_login(self) -> MyQLoginSession:
        if self._login is None:
            raise RuntimeError("The MyQ config flow has no login session")
        return self._login

"""
This plugin searches for Telegram bot tokens
"""
import re

import requests

from detect_secrets.core.constants import VerifiedResult
from .base import RegexBasedDetector


class TelegramBotTokenDetector(RegexBasedDetector):
    """Scans for Telegram bot tokens."""
    secret_type = 'Telegram Bot Token'

    denylist = [
        # refs https://core.telegram.org/bots/api#authorizing-your-bot
        re.compile(r'(?<![:\w])\d{8,10}:[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])'),
    ]

    def verify(self, token, *args, **kwargs):  # pragma: no cover
        try:
            response = requests.get(
                'https://api.telegram.org/bot{}/getMe'.format(
                    token,
                ),
                timeout=5,
            )
        except requests.exceptions.RequestException:
            return VerifiedResult.UNVERIFIED

        if response.status_code == 200:
            return VerifiedResult.VERIFIED_TRUE
        if response.status_code == 401:
            return VerifiedResult.VERIFIED_FALSE

        return VerifiedResult.UNVERIFIED

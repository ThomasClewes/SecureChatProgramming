from __future__ import annotations

import re

from typing import Union

_recipient_pattern = re.compile(r"^@(\S+)\b")

#existing chat only allows single recipients, and only at the start of a message,
#so this follows the same limitations.
def extract_recipient(message:str)->Union[str,None]:
    match = _recipient_pattern.match(str(message))
    if match:
        return match.group(1)
    else:
        return None

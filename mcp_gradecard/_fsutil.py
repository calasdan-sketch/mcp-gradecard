"""Writing a file so that a reader never sees half of it.

`os.replace` can fail on Windows with PermissionError while another program
(an editor, a virus scanner, a sync client) holds the target open for a
moment; a short retry turns that into a success instead of a failed report.
"""

from __future__ import annotations

import os
import tempfile
import time


_RETRY = os.name == "nt"


def replace(src: str, dst: str, tries: int = 5, wait: float = 0.1) -> None:
    """`os.replace`, tried again a few times when the target is busy."""
    for attempt in range(tries):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == tries - 1 or not _RETRY:
                raise
            time.sleep(wait * (attempt + 1))


def write_text_atomic(path: str, text: str) -> None:
    """Write `text` to `path` as UTF-8 with LF line ends, in one step.

    The old file stays if anything fails. Raises OSError (not for a directory
    or an unwritable folder: the caller words the message).
    """
    if os.path.isdir(path):
        raise IsADirectoryError(21, "is a directory", path)
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".mcp-gradecard-out.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        try:  # a plain report is readable by whoever could read the old one
            os.chmod(tmp, 0o644 if not os.path.exists(path)
                     else os.stat(path).st_mode & 0o7777)
        except OSError:
            pass
        replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

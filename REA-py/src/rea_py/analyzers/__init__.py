"""Importing this package registers every analyzer with the tool registry."""
from . import (  # noqa: F401
    apk,
    elf,
    filetype,
    gobuild,
    har,
    javascript,
    macho,
    models,
    pe,
    sqlite_db,
    strings_tool,
)

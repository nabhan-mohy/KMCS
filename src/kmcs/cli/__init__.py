"""KMCS command-line interface package.

The CLI is a thin control surface: it parses arguments, validates them, calls the
application/service layer (target manager, campaign manager, corpus manager,
analysis, reproduction, reporting) and prints the *real* result.  It never
implements fuzzing, analysis or persistence logic itself.
"""

from kmcs.cli.commands import main, run_command

__all__ = ["main", "run_command"]

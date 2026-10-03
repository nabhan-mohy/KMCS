# KMCS — Defensive Fuzzing & Crash-Analysis Platform

## Quick start (Kali Linux)

    git clone https://github.com/nabhan-mohy/KMCS.git
    cd KMCS
    python3 -m venv .venv
    source .venv/bin/activate
    pip install pydantic sqlalchemy pytest

    sudo apt install -y afl++ clang llvm gdb

    export PYTHONPATH=$PWD/src

    # Verify the environment
    python -m kmcs.cli.commands doctor

    # Register a target
    python -m kmcs.cli.commands target add my_target --command /path/to/binary --sanitizer asan

    # Add at least one seed
    echo "AAAA" > kmcs-workspace/corpus/seed1

    # Run a 60-second campaign
    python -m kmcs.cli.commands campaign start --target my_target --duration 60 --fuzzer aflpp --foreground

    # Import crashes and generate reports
    python -m kmcs.cli.commands crash import
    python -m kmcs.cli.commands report generate --format html --output report.html

# Copyright (c) 2026 GUN-101-TPM contributors
# SPDX-License-Identifier: MIT

"""Build reproducible wheel and source distributions."""

import argparse
import copy
import gzip
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile


def normalize_sdist(path: Path, epoch: int) -> None:
    """Normalize source archive metadata so repeated builds have stable bytes."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with tarfile.open(path, "r:gz") as source:
        members = []
        for member in source.getmembers():
            item = copy.copy(member)
            item.mtime = epoch
            item.uid = 0
            item.gid = 0
            item.uname = ""
            item.gname = ""
            item.pax_headers = {}
            data = source.extractfile(member).read() if member.isfile() else None
            members.append((item, data))

    members.sort(key=lambda item: item[0].name)
    with temporary.open("wb") as raw:
        with gzip.GzipFile(
            filename="", fileobj=raw, mode="wb", mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as output:
                for member, data in members:
                    output.addfile(member, None if data is None else io.BytesIO(data))
    os.replace(temporary, path)


def main() -> None:
    """Build distributions and normalize the source archive."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(output)],
        check=True,
    )
    for archive in output.glob("*.tar.gz"):
        normalize_sdist(archive, epoch)


if __name__ == "__main__":
    main()

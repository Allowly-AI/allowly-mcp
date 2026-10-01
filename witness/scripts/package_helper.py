#!/usr/bin/env python3
"""Build and package the native customer helper for an Allowly CLI release.

Binary archives contain one executable. The source archive contains only the
pinned Rust adapter and its two build scripts, with flat-root regular entries.
Release metadata stays outside archives so the CLI can pin SHA256SUMS.
"""

import argparse
import gzip
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
NAME = "allowly-witness-poc"
TARGETS = {
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
}
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
SOURCE_REQUIRED = {
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "src/main.rs",
    "scripts/prepare_tlsn.sh", "scripts/cargo.sh",
}


def cargo_version():
    data = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    package = re.search(r"(?ms)^\[package\]\s*$(.*?)(?=^\[|\Z)", data)
    if package is None:
        raise ValueError("Cargo.toml has no [package] section")
    version = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', package.group(1), re.M)
    if version is None:
        raise ValueError("Cargo.toml has no simple semantic package version")
    return version.group(1)


def cargo_host():
    result = subprocess.run(
        ["bash", "scripts/cargo.sh", "-vV"], cwd=ROOT, check=True,
        stdout=subprocess.PIPE, text=True,
    )
    match = re.search(r"^host: (\S+)$", result.stdout, re.M)
    if match is None:
        raise ValueError("could not determine Cargo host target")
    return match.group(1)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def archive_bytes(binary):
    """Use fixed tar metadata and gzip timestamp for repeatable packaging."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            entry = tarfile.TarInfo(NAME)
            entry.size = len(binary)
            entry.mode = 0o755
            entry.mtime = 0
            entry.uid = 0
            entry.gid = 0
            entry.uname = ""
            entry.gname = ""
            tar.addfile(entry, io.BytesIO(binary))
    return output.getvalue()


def source_archive_bytes():
    """Package buildable adapter source, never vendored TLSNotary or secrets."""
    paths = sorted(SOURCE_REQUIRED | {
        path.relative_to(ROOT).as_posix() for path in (ROOT / "src").rglob("*")
        if path.is_file() or path.is_symlink()
    })
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name in paths:
                path = ROOT / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError("source must be a regular file: " + name)
                data = path.read_bytes()
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o755 if name.startswith("scripts/") else 0o644
                entry.mtime = entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                tar.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def check_source_archive(path):
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("source archive exceeds size limit")
    with tarfile.open(path, "r:gz") as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        if len(members) > 256 or len(names) != len(set(names)):
            raise ValueError("source archive has duplicate or excessive entries")
        if not SOURCE_REQUIRED.issubset(names):
            raise ValueError("source archive is missing required files")
        if sum(member.size for member in members) > MAX_SOURCE_BYTES:
            raise ValueError("expanded source archive exceeds size limit")
        for member in members:
            allowed = member.name in SOURCE_REQUIRED or re.fullmatch(
                r"src/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.rs", member.name,
            )
            if not allowed or not member.isfile() or member.pax_headers:
                raise ValueError("unexpected source archive entry: " + member.name)
            mode = 0o755 if member.name.startswith("scripts/") else 0o644
            if (member.mode != mode or member.mtime != 0 or member.uid != 0
                    or member.gid != 0 or member.uname or member.gname):
                raise ValueError("unexpected source archive metadata: " + member.name)
    return cargo_version(), "source"


def check_binary_target(binary, target):
    """Reject a mislabeled archive before the CLI selects it for a platform."""
    if target.endswith("-apple-darwin"):
        if len(binary) < 32 or binary[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("archive is not a native 64-bit macOS executable")
        machine = int.from_bytes(binary[4:8], "little")
        expected = 0x0100000C if target.startswith("aarch64-") else 0x01000007
    else:
        if len(binary) < 64 or binary[:6] != b"\x7fELF\x02\x01":
            raise ValueError("archive is not a native 64-bit Linux executable")
        machine = int.from_bytes(binary[18:20], "little")
        expected = 183 if target.startswith("aarch64-") else 62
    if machine != expected:
        raise ValueError("archive executable architecture does not match " + target)


def check_archive(path):
    match = re.fullmatch(
        re.escape(NAME) + r"-([0-9]+\.[0-9]+\.[0-9]+)-(.+)\.tar\.gz", path.name,
    )
    if match is None or match.group(2) not in TARGETS:
        if match is not None and match.group(2) == "source":
            version, target = check_source_archive(path)
            return match.group(1), target
        raise ValueError("unexpected helper archive name: " + path.name)
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("helper archive exceeds size limit")
    with tarfile.open(path, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) != 1 or members[0].name != NAME or not members[0].isfile():
            raise ValueError("helper archive must contain only a root-level executable")
        if members[0].mode != 0o755:
            raise ValueError("helper archive executable mode must be 0755")
        if members[0].size > MAX_BINARY_BYTES:
            raise ValueError("helper executable exceeds size limit")
        content = tar.extractfile(members[0]).read()
        if not content:
            raise ValueError("helper archive contains an empty binary")
        check_binary_target(content, match.group(2))
    return match.group(1), match.group(2)


def checksum_lines(directory):
    archives = sorted(directory.glob(NAME + "-*.tar.gz"))
    if not archives:
        raise ValueError("no helper archives found in " + str(directory))
    versions = set()
    targets = set()
    lines = []
    for archive in archives:
        version, target = check_archive(archive)
        versions.add(version)
        if target in targets:
            raise ValueError("duplicate helper target: " + target)
        targets.add(target)
        lines.append("{}  {}\n".format(sha256(archive.read_bytes()), archive.name))
    if versions != {cargo_version()}:
        raise ValueError("archive version does not match Cargo.toml")
    return "".join(lines).encode("ascii")


def require_release_source():
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("release packaging requires a clean checkout; use --local for tests")
    tags = subprocess.check_output(
        ["git", "tag", "--points-at", "HEAD"], cwd=ROOT, text=True,
    ).splitlines()
    if "witness-v" + cargo_version() not in tags:
        raise ValueError("HEAD must have tag witness-v" + cargo_version())


def write_archive(directory, filename, contents, local):
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / filename
    if archive.exists() and archive.read_bytes() != contents:
        raise ValueError("existing archive differs: " + str(archive))
    archive.write_bytes(contents)
    check_archive(archive)
    print("{} sha256:{}".format(archive, sha256(contents)))
    if local:
        print("Local test archive; do not publish from a dirty or untagged checkout.")


def source(directory, local):
    if not local:
        require_release_source()
    filename = "{}-{}-source.tar.gz".format(NAME, cargo_version())
    write_archive(directory, filename, source_archive_bytes(), local)


def build(directory, local, offline):
    if not local:
        require_release_source()
    host = cargo_host()
    if host not in TARGETS:
        raise ValueError("unsupported native target: " + host)
    subprocess.run(["bash", "scripts/prepare_tlsn.sh"], cwd=ROOT, check=True)
    command = ["bash", "scripts/cargo.sh", "build", "--release", "--locked"]
    if offline:
        command.append("--offline")
    command += ["--bin", NAME]
    subprocess.run(command, cwd=ROOT, check=True)
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    binary = target_dir / "release" / NAME
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Cargo did not produce an executable helper")
    binary_bytes = binary.read_bytes()
    if len(binary_bytes) > MAX_BINARY_BYTES:
        raise ValueError("helper executable exceeds size limit")
    check_binary_target(binary_bytes, host)
    filename = "{}-{}-{}.tar.gz".format(NAME, cargo_version(), host)
    write_archive(directory, filename, archive_bytes(binary_bytes), local)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build", help="build a native, versioned helper archive")
    build_parser.add_argument("--output", type=Path, default=ROOT / "dist")
    build_parser.add_argument("--local", action="store_true", help="permit dirty or untagged local tests")
    build_parser.add_argument("--offline", action="store_true", help="use cached Cargo crates only")
    source_parser = sub.add_parser("source", help="package pinned source for a local Rust build")
    source_parser.add_argument("--output", type=Path, default=ROOT / "dist")
    source_parser.add_argument("--local", action="store_true", help="permit dirty or untagged local tests")
    for name in ("manifest", "verify"):
        part = sub.add_parser(name, help="write or verify SHA256SUMS for all archives")
        part.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        if args.command == "build":
            build(args.output, args.local, args.offline)
        elif args.command == "source":
            source(args.output, args.local)
        else:
            expected = checksum_lines(args.output)
            checksum_file = args.output / "SHA256SUMS"
            if args.command == "manifest":
                checksum_file.write_bytes(expected)
                print("{} sha256:{}".format(checksum_file, sha256(expected)))
            elif not checksum_file.is_file() or checksum_file.read_bytes() != expected:
                raise ValueError("SHA256SUMS does not match the packaged archives")
            else:
                print("SHA256SUMS verified; sha256:{}".format(sha256(expected)))
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.exit(1, "{}\n".format(error))


if __name__ == "__main__":
    main()

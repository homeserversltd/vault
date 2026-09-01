#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, re, subprocess, tarfile, tempfile
import urllib.error, urllib.parse, urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

OWNER_REPO = "HOMESERVERSLTD/vault"
REPOSITORY = f"forgejo:{OWNER_REPO}"
API = "https://git.home.arpa/api/v1"
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

class ReleaseFailure(Exception):
    """Safe failure text; never include credentials in receipts."""

def fail(message: str) -> None:
    raise ReleaseFailure(message)

def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.STDOUT).strip()
    except Exception:
        fail(f"git command failed: {' '.join(args)}")
    raise AssertionError

def request(url: str, token: str, method: str = "GET", data: bytes | None = None,
            content_type: str | None = None, accept: str = "application/json") -> tuple[int, bytes]:
    headers = {"Authorization": f"token {token}", "Accept": accept}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=180) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except Exception:
        fail(f"Forgejo {method} request failed")
    raise AssertionError

def json_request(url: str, token: str, method: str = "GET",
                 payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    status, body = request(url, token, method, data, "application/json" if data else None)
    if not body:
        return status, None
    try:
        return status, json.loads(body)
    except Exception:
        fail("Forgejo returned invalid JSON")
    raise AssertionError

def verify_tag_head(tag_url: str, token: str, source: str, required: bool) -> None:
    status, tag = json_request(tag_url, token)
    if status == 404 and not required:
        return
    if status != 200 or not isinstance(tag, dict):
        fail("tag lookup returned an invalid tag")
    commit = tag.get("commit")
    if not isinstance(commit, dict) or not isinstance(commit.get("id"), str):
        fail("tag lookup returned no commit id")
    if commit["id"] != source:
        fail("version tag does not resolve to CI_COMMIT_SHA")

def read_inputs() -> tuple[str, list[str]]:
    raw = Path("VERSION").read_bytes()
    line = raw[:-1] if raw.endswith(b"\n") else raw
    if not line or b"\n" in line or b"\r" in line:
        fail("VERSION must contain exactly one nonempty line")
    try:
        base = line.decode("ascii")
    except UnicodeDecodeError:
        fail("VERSION must be ASCII")
    if not SEMVER.fullmatch(base):
        fail(f"invalid VERSION {base!r}")
    try:
        manifest = json.loads(Path("manifest.json").read_text())
    except Exception:
        fail("cannot read manifest.json")
    files = manifest.get("payload_files") if isinstance(manifest, dict) and manifest.get("repo") == OWNER_REPO else None
    if not isinstance(files, list) or not files or any(not isinstance(x, str) for x in files):
        fail("invalid or missing payload_files")
    if len(files) != len(set(files)):
        fail("duplicate payload file")
    for name in files:
        path = PurePosixPath(name)
        if not name or path.is_absolute() or ".." in path.parts or str(path) != name:
            fail(f"invalid payload path {name!r}")
        try:
            mode = int(git("ls-files", "--stage", "--error-unmatch", "--", name).split()[0], 8)
        except Exception:
            fail(f"payload is not tracked: {name}")
        if mode & 0o170000 != 0o100000 or not Path(name).is_file() or Path(name).is_symlink():
            fail(f"payload is not a regular file: {name}")
    return base, sorted(files)

def source_head() -> str:
    current = git("rev-parse", "HEAD")
    ci = os.environ.get("CI_COMMIT_SHA", "")
    if not FULL_SHA.fullmatch(current) or not FULL_SHA.fullmatch(ci):
        fail("HEAD and CI_COMMIT_SHA must be full lowercase 40-hex values")
    if current != ci:
        fail("HEAD does not equal CI_COMMIT_SHA")
    return current

def make_tar(files: list[str], output: Path) -> None:
    """Tar exactly sorted manifest files; version is base VERSION plus full HEAD."""
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name in files:
            path = Path(name)
            tracked = int(git("ls-files", "--stage", "--", name).split()[0], 8)
            info = tarfile.TarInfo(name)
            info.size = path.stat().st_size
            info.mode = 0o755 if tracked & 0o111 else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            with path.open("rb") as source:
                archive.addfile(info, source)

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()

def list_assets(release_id: int, token: str) -> dict[str, dict[str, Any]]:
    status, value = json_request(f"{API}/repos/{OWNER_REPO}/releases/{release_id}/assets", token)
    if not 200 <= status < 300 or not isinstance(value, list):
        fail("release assets could not be listed")
    result: dict[str, dict[str, Any]] = {}
    for asset in value:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail("release contains an invalid asset")
        if asset["name"] in result:
            fail(f"duplicate asset {asset['name']}")
        result[asset["name"]] = asset
    return result

def upload(release_id: int, path: Path, token: str) -> None:
    url = f"{API}/repos/{OWNER_REPO}/releases/{release_id}/assets?name={urllib.parse.quote(path.name, safe='')}"
    status, _ = request(url, token, "POST", path.read_bytes(), "application/octet-stream")
    if not 200 <= status < 300:
        fail("asset upload failed")

def verify_asset(asset: dict[str, Any], path: Path, token: str, expected_sha: str) -> None:
    asset_id = asset.get("id")
    if not isinstance(asset_id, int):
        fail(f"asset {path.name} has no id")
    status, body = request(f"{API}/repos/{OWNER_REPO}/releases/assets/{asset_id}", token,
                           accept="application/octet-stream")
    if not 200 <= status < 300 or body != path.read_bytes():
        fail(f"downloaded asset differs: {path.name}")
    if path.suffix == ".tar" and hashlib.sha256(body).hexdigest() != expected_sha:
        fail("downloaded tar digest mismatch")

def emit(context: dict[str, Any], count: int, status: str, outcome: str,
         ok: bool, changed: bool, error: str | None = None) -> None:
    result: dict[str, Any] = {
        "schema": "vault.release_publish.v1", "repository": REPOSITORY,
        "source_head": context.get("source_head"), "version": context.get("version"),
        "tag": context.get("tag"), "artifact": context.get("artifact"),
        "sidecar": context.get("sidecar"), "sha256": context.get("sha256"),
        "payload_files": count, "status": status, "outcome": outcome,
        "ok": ok, "changed": changed,
    }
    if error:
        result["error"] = error
    print(json.dumps(result, separators=(",", ":")))

def main() -> None:
    count = 0
    context: dict[str, Any] = {}
    try:
        token = os.environ.get("FORGEJO_TOKEN", "")
        if not token:
            fail("FORGEJO_TOKEN is required")
        if os.environ.get("CI_COMMIT_BRANCH") != "main":
            fail("publisher requires CI_COMMIT_BRANCH=main")
        if os.environ.get("CI_REPO") != OWNER_REPO:
            fail("publisher requires the owned CI_REPO")
        remote = git("config", "--get", "remote.origin.url")
        match = re.fullmatch(r"git@([^:/:]+):([^/]+)/([^/]+?)(?:\.git)?", remote)
        if not match or match.group(1) != "git.home.arpa" or f"{match.group(2)}/{match.group(3)}" != OWNER_REPO:
            fail("origin is not the exact owned repository")
        source = source_head()
        base, files = read_inputs()
        count = len(files)
        version = f"{base}-g{source}"
        artifact_name = f"vault-{version}.tar"
        sidecar_name = f"{artifact_name}.sha256"
        context = {"source_head": source, "version": version, "tag": version,
                   "artifact": artifact_name, "sidecar": sidecar_name}
        with tempfile.TemporaryDirectory(prefix="vault-release-") as directory:
            artifact = Path(directory) / artifact_name
            sidecar = Path(directory) / sidecar_name
            make_tar(files, artifact)
            expected_sha = sha256(artifact)
            sidecar.write_text(f"{expected_sha}  {artifact_name}\n")
            context["sha256"] = expected_sha
            base_url = f"{API}/repos/{OWNER_REPO}"
            tag_url = f"{base_url}/releases/tags/{urllib.parse.quote(version, safe='')}"
            forgejo_tag_url = f"{base_url}/tags/{urllib.parse.quote(version, safe='')}"
            verify_tag_head(forgejo_tag_url, token, source, required=False)
            status, release = json_request(tag_url, token)
            created = False
            if status == 404:
                create_status, release = json_request(
                    f"{base_url}/releases", token, "POST",
                    {"tag_name": version, "name": version, "body": f"vault payload {version}",
                     "target_commitish": source, "draft": False, "prerelease": False},
                )
                if create_status == 409:
                    status, release = json_request(tag_url, token)
                elif not 200 <= create_status < 300:
                    fail("release creation failed")
                else:
                    status = create_status
                    created = True
            if not 200 <= status < 300 or not isinstance(release, dict):
                fail("release lookup returned an invalid release")
            release_id = release.get("id")
            if not isinstance(release_id, int) or release.get("tag_name") != version:
                fail("release lookup returned a tag mismatch")
            verify_tag_head(forgejo_tag_url, token, source, required=True)
            assets = list_assets(release_id, token)
            expected_names = {artifact_name, sidecar_name}
            if set(assets) - expected_names:
                fail("release contains unexpected assets")
            changed = created
            if set(assets) != expected_names:
                if not created:
                    fail("existing release is missing the exact asset pair")
                upload(release_id, artifact, token)
                upload(release_id, sidecar, token)
                assets = list_assets(release_id, token)
                if set(assets) != expected_names:
                    fail("release assets are not the exact pair")
                changed = True
            for path in (artifact, sidecar):
                verify_asset(assets[path.name], path, token, expected_sha)
        emit(context, count, "success", "published" if changed else "verified_noop", True, changed)
    except ReleaseFailure as error:
        emit(context, count, "failure", "failed", False, False, str(error))
        raise SystemExit(1)
    except Exception:
        emit(context, count, "failure", "failed", False, False, "publisher failed unexpectedly")
        raise SystemExit(1)

if __name__ == "__main__":
    main()

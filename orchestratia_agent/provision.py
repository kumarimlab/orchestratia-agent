"""Provision the restricted OS user, its workspace ACLs, and the sudoers rule.

Root-only, run once per box. Kept out of cli.py because it is security-sensitive
and needs its own tests: the equivalent bastion script shipped a newline-injection
hole that visudo parsed as a second, entirely valid rule.

Everything here validates before it acts, and nothing is applied partially.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

# Deliberately strict: this feeds a sudoers file. Anything outside this charset
# is refused rather than escaped, because escaping is where the bugs live.
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# An absolute path, no whitespace, no sudoers metacharacters.
TMUX_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
GIT_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
BIN_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")   # code-server et al.

# Granting any of these -- OR ANYTHING BENEATH THEM -- would hand back what the
# tier removes. Checked as ancestors, not as exact strings: an exact-match test
# refused /etc but happily allowed /etc/cron.d, /etc/sudoers.d and /root/.ssh,
# each of which is a direct route back to root.
FORBIDDEN_TREES = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
    "/root", "/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run",
    "/var/spool",
)

# Allowed as an ancestor of a workspace, but never AS one -- granting the whole
# tree would cover every project on the box.
FORBIDDEN_EXACT = {"/", "/home", "/srv", "/opt", "/tmp", "/var", "/mnt", "/media"}

# Credential STORES, not tool folders: project repos routinely contain `.claude/` and
# `.orchestratia/` (settings, memory), so those are matched on the secret itself.
SENSITIVE_ENTRIES = (".ssh", ".gnupg", ".aws", ".kube",
                     os.path.join(".config", "gcloud"),
                     os.path.join(".docker", "config.json"),
                     os.path.join(".claude", ".credentials.json"),
                     os.path.join(".orchestratia", "ssh_keys"))
ORCHESTRATIA_PATHS = ("/opt/orchestratia-agent", "/opt/orchestratia-venv")

RESERVED_USERS = {"root", "daemon", "bin", "sys", "adm", "sudo", "docker"}

# NOT a denylist. A denylist of "the dangerous groups" missed lxd (container
# escape to root), disk (raw block devices) and shadow (read /etc/shadow) --
# each of which defeats the tier on its own. The user is instead asserted to
# have NO supplementary groups at all, which is the only version of this check
# that cannot be out-of-date.
ALLOWED_SUPPLEMENTARY_GROUPS: tuple[str, ...] = ()


class ProvisionError(Exception):
    """Refuse to provision. Never partially apply."""


def validate_username(name: str) -> str:
    if not isinstance(name, str) or not USERNAME_RE.match(name):
        raise ProvisionError(
            f"invalid username {name!r}: must match {USERNAME_RE.pattern}"
        )
    if name in RESERVED_USERS:
        raise ProvisionError(f"{name!r} is not a restricted user")
    return name


def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def validate_workspace(path: str) -> str:
    """Resolve and authorise a workspace path, or refuse.

    Resolves with realpath BEFORE checking, because setfacl follows a symlinked
    argument: a workspace symlinked to / would otherwise ACL the whole
    filesystem. A symlink is refused outright rather than silently followed, so
    what the operator typed is what gets granted.
    """
    if not isinstance(path, str) or any(c in path for c in "\n\r\t\0"):
        raise ProvisionError(f"invalid workspace {path!r}: control characters")
    if not path.startswith("/"):
        raise ProvisionError(f"workspace {path!r} must be an absolute path")

    normalised = os.path.normpath(path)
    # normpath keeps a leading '//' (POSIX-permitted), which also made the
    # parent walk below non-terminating. Collapse it.
    while normalised.startswith("//"):
        normalised = normalised[1:]

    if os.path.islink(normalised):
        raise ProvisionError(
            f"refusing to grant {normalised!r}: it is a symlink, and setfacl "
            f"would apply the grant to its target instead"
        )

    resolved = os.path.realpath(normalised)
    if resolved != normalised:
        raise ProvisionError(
            f"refusing to grant {normalised!r}: it resolves to {resolved!r} "
            f"(grant the real path explicitly)"
        )

    if resolved in FORBIDDEN_EXACT:
        raise ProvisionError(
            f"refusing to grant {resolved!r}: granting the whole tree would "
            f"cover every project on this box"
        )
    for tree in FORBIDDEN_TREES:
        if _is_within(resolved, tree):
            raise ProvisionError(
                f"refusing to grant {resolved!r}: it is inside {tree!r}, "
                f"which would defeat the tier"
            )
    _validate_not_home_internals(resolved)
    _validate_not_orchestratia(resolved)
    for entry in SENSITIVE_ENTRIES:
        if os.path.lexists(os.path.join(resolved, entry)):
            raise ProvisionError(f"refusing to grant {resolved!r}: it contains {entry} (credentials)")
    # ...and never one INSIDE a store: refusing only the folder that contains .ssh let
    # `--workspace /home/dev/.ssh` through, ACL'ing the daemon user's private key.
    parts = _casefolded_parts(resolved)
    for entry in SENSITIVE_ENTRIES:
        e = _casefolded_parts(entry)
        if any(parts[i:i + len(e)] == e for i in range(len(parts) - len(e) + 1)):
            raise ProvisionError(f"refusing to grant {resolved!r}: it is inside {entry} (credentials)")
    return resolved


def _casefolded_parts(path: str) -> list[str]:
    # Case-folded because macOS homes are case-insensitive: ~/.SSH is ~/.ssh there.
    return [p.casefold() for p in path.split(os.sep) if p]


def _validate_not_home_internals(resolved: str) -> None:
    """A home, anything above one, and the parts of one its owner depends on.

    A recursive rwX ACL on a home hands over its ~/.ssh — a path to that user and then
    root. The same holds one level down: the top-level dot-folders hold credentials and
    programs the owner runs (~/.config/gh tokens, ~/.local/share/orchestratia/code-server),
    and ~/bin is on the owner's PATH. A project folder inside a home is fine.
    """
    for home in _home_dirs():
        if resolved == home:
            raise ProvisionError(
                f"refusing to grant {resolved!r}: it is a user's home directory — granting it "
                f"would expose ~/.ssh and other credentials; grant a project folder inside it"
            )
        if _is_within(home, resolved):
            raise ProvisionError(
                f"refusing to grant {resolved!r}: it contains the home directory {home!r}"
            )
        if _is_within(resolved, home):
            first = os.path.relpath(resolved, home).split(os.sep)[0]
            if first.startswith(".") or first.casefold() == "bin":
                raise ProvisionError(
                    f"refusing to grant {resolved!r}: {os.path.join(home, first)!r} holds that "
                    f"user's credentials, settings or programs; grant a project folder instead"
                )


def _home_dirs(entries=None) -> set[str]:
    """Every person's home on the box, plus /root and the caller's own.

    A person is a login account — uid 1000 and up (not nobody) — or any account housed
    under /home or /Users. Service accounts are not: www-data's /var/www must stay
    grantable as a place projects live.
    """
    import pwd
    homes = {"/root"}
    for pw in (pwd.getpwall() if entries is None else entries):
        home = pw.pw_dir
        if not home or home == "/":
            continue
        person = 1000 <= pw.pw_uid < 65534 or home.startswith(("/home/", "/Users/"))
        if person and os.path.isdir(home):
            homes.add(os.path.realpath(home))
    if entries is None:
        try:
            homes.add(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))
        except KeyError:
            pass
    return homes


def _validate_not_orchestratia(resolved: str) -> None:
    for root in ORCHESTRATIA_PATHS:
        if _is_within(resolved, root):
            raise ProvisionError(f"refusing to grant {resolved!r}: it is part of Orchestratia's own install")


def sudoers_lines(daemon_user: str, projects: dict, tmux_path: str, git_path: str,
                  code_server_path: str | None = None) -> list[str]:
    """One pinned, downward-only rule per project user.

    Each line permits exactly tmux, git, and (when provided) code-server as that
    project's user — nothing else, no wildcards, no shell, no ALL target. git is
    included so `git_changes` can inspect a repo AS the session's own
    unprivileged user; code-server so the editor runs as that user too.

    Still not an escalation: every orcp-* user has strictly LESS power than the
    daemon user, so letting the daemon run these as one is a downward move.

    The caller joins these with newlines into a drop-in and validates the whole
    file with `visudo -cf` before moving it into place — the belt to this
    braces, because a sudoers newline-injection once shipped here.
    """
    validate_username(daemon_user)
    if not isinstance(tmux_path, str) or not TMUX_PATH_RE.match(tmux_path):
        raise ProvisionError(f"invalid tmux path {tmux_path!r}")
    if not isinstance(git_path, str) or not GIT_PATH_RE.match(git_path):
        raise ProvisionError(f"invalid git path {git_path!r}")
    cmds = f"{tmux_path}, {git_path}"
    if code_server_path:
        if not BIN_PATH_RE.match(code_server_path):
            raise ProvisionError(f"invalid code-server path {code_server_path!r}")
        cmds += f", {code_server_path}"
    lines = []
    for spec in projects.values():
        user = validate_username((spec or {}).get("user"))
        lines.append(f"{daemon_user} ALL=({user}) NOPASSWD: {cmds}")
    return lines


def assert_no_collision(user: str, project_id: str, existing_projects: dict) -> None:
    """Refuse if `user` already belongs to a DIFFERENT project (D3).

    project_username derives the name from 12 hex of the project UUID; a
    collision is astronomically unlikely but its blast radius is a cross-tenant
    breach — two projects sharing one UID — so it is asserted, not assumed.
    Re-provisioning the same project is fine (idempotent).
    """
    for pid, spec in (existing_projects or {}).items():
        if (spec or {}).get("user") == user and pid != project_id:
            raise ProvisionError(
                f"username {user!r} already maps to project {pid!r}; refusing to "
                f"reuse it for {project_id!r} (hash collision — pick distinct projects)"
            )


def acl_commands(user: str, workspace: str) -> list[list[str]]:
    """Grant rwX on the workspace, and traverse-only on every parent.

    A repo inside a 0750 home is unreachable without the parent traverse bit,
    even with a perfect ACL on the repo itself — verified on a real box, and
    the single most confusing failure this feature can produce.

    Traverse is `--x`, NEVER `r-x`: `r-x` would let the restricted user list the
    parent's contents.

    HONEST LIMIT — do not overstate this. `--x` blocks directory LISTING and
    blocks reads of 0600 files, but it does NOT hide world-readable content on
    a known path. With a workspace under /home/ubuntu, the restricted user can
    still read ~/.bashrc, ~/.gitconfig and anything in ~/.claude that carries
    world bits. Only mode-0600 material (~/.ssh, ~/.claude/.credentials.json)
    is actually protected.

    So: prefer workspaces OUTSIDE user homes. provision() warns when a granted
    workspace requires punching traverse through a home directory.
    """
    user = validate_username(user)
    workspace = validate_workspace(workspace)
    # -P so setfacl does not follow symlinks while recursing.
    # NO -d (default) ACL: that would make files the DAEMON user creates later
    # writable by the agent, and the daemon routinely executes code from these
    # directories (build scripts, git hooks, node_modules/.bin). An agent that
    # can rewrite a script the root-equivalent daemon later runs has escaped the
    # tier in one step -- proven in review. New agent-created files are owned by
    # the agent anyway, so the default ACL bought nothing it needed.
    cmds = [["setfacl", "-P", "-R", "-m", f"u:{user}:rwX", workspace]]

    parent = os.path.dirname(workspace)
    while True:
        nxt = os.path.dirname(parent)
        if parent == nxt:          # reached the root; dirname('/') == '/'
            break
        cmds.append(["setfacl", "-m", f"u:{user}:--x", parent])
        parent = nxt
    return cmds


def merge_project_workspaces(existing_projects: dict, project_id: str, user: str,
                             spaces: list[str]) -> dict:
    """Add `spaces` to the project's recorded workspaces. Never drops one.

    The config is the only record of what was granted. Replacing the list left the
    dropped folders' ACLs on disk with nothing showing them — found on staging as a
    locked-down user still able to read the daemon user's SSH key. Removal is the
    explicit --revoke-workspace, which takes the access away along with the record.

    A recorded grant that validation now refuses blocks re-provisioning until it is
    revoked, rather than being carried forward as if it were fine.
    """
    merged = {pid: dict(spec or {}) for pid, spec in (existing_projects or {}).items()}
    recorded = list((merged.get(project_id) or {}).get("workspaces") or [])
    for w in recorded:
        try:
            validate_workspace(w)
        except ProvisionError as e:
            raise ProvisionError(
                f"project {project_id} already has a grant that is no longer allowed ({e}). "
                f"Remove it first: sudo orchestratia-agent provision-tier --project {project_id} "
                f"--revoke-workspace {w}"
            ) from e
    for w in spaces:
        if w not in recorded:
            recorded.append(w)
    merged[project_id] = {**(merged.get(project_id) or {}), "user": user, "workspaces": recorded}
    return merged


def _normalise_for_revoke(path: str) -> str:
    """Shape checks only. Removing access must work for exactly the paths that
    validate_workspace would now refuse, so its policy checks do not apply here."""
    if not isinstance(path, str) or any(c in path for c in "\n\r\t\0"):
        raise ProvisionError(f"invalid workspace {path!r}: control characters")
    if not path.startswith("/"):
        raise ProvisionError(f"workspace {path!r} must be an absolute path")
    normalised = os.path.normpath(path)
    while normalised.startswith("//"):
        normalised = normalised[1:]
    if normalised == "/":
        raise ProvisionError("refusing to revoke '/': name the workspace that was granted")
    # setfacl -P silently SKIPS a symlink argument and exits 0, which would report a
    # revoke that never happened.
    if os.path.islink(normalised):
        raise ProvisionError(f"refusing to revoke {normalised!r}: it is a symlink; name the real path")
    if os.path.lexists(normalised) and os.path.realpath(normalised) != normalised:
        raise ProvisionError(
            f"refusing to revoke {normalised!r}: it resolves to {os.path.realpath(normalised)!r}"
        )
    return normalised


def revoke_commands(user: str, workspace: str, remaining: list[str]) -> list[list[str]]:
    """Take one workspace grant away: its recursive ACL and its parents' traverse.

    A parent's traverse entry may also serve a workspace that stays, and a remaining
    workspace inside the revoked tree loses its own grant to the recursive removal. So
    what remains is re-applied afterwards — fully where it overlaps the revoked tree,
    traverse-only elsewhere (a recursive re-grant of an unrelated repo is just slow).
    """
    user = validate_username(user)
    workspace = _normalise_for_revoke(workspace)
    for w in remaining:
        if _is_within(workspace, w):
            raise ProvisionError(
                f"refusing to revoke {workspace!r}: it is inside the workspace {w!r}, whose "
                f"grant still covers it; revoke {w!r} instead"
            )
    cmds = [["setfacl", "-P", "-R", "-x", f"u:{user}", workspace]]
    parent = os.path.dirname(workspace)
    while True:
        nxt = os.path.dirname(parent)
        if parent == nxt:
            break
        cmds.append(["setfacl", "-x", f"u:{user}", parent])
        parent = nxt
    for w in remaining:
        grant = acl_commands(user, w)
        cmds.extend(grant if _is_within(w, workspace) else grant[1:])
    return cmds


def _acl_perms(getfacl_output: str, user: str) -> str | None:
    """The named user's permission triple in `getfacl` output, or None."""
    prefix = f"user:{user}:"
    for line in getfacl_output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):len(prefix) + 3]
    return None


def workspace_lockdown_command(workspace: str) -> list[str]:
    """Remove ALL 'other' access from the workspace root dir.

    Per-project users each get --x traverse on the SHARED parent (e.g. /srv), so
    without this a world-readable workspace (a 0755 git checkout is world-
    readable) is readable by a sibling project's user — a cross-tenant leak the
    ACLs alone do not close, because an ACL grants the named user access without
    removing 'other' access. `chmod o=` on the workspace root blocks traverse-in
    for everyone who is neither the owner nor the ACL-granted project user; files
    inside are then unreachable by 'other' regardless of their own mode bits.

    Not recursive: blocking traverse at the root is sufficient and leaves the
    operator's file modes untouched.
    """
    workspace = validate_workspace(workspace)
    return ["chmod", "o=", workspace]


def _strip_supplementary_groups(user: str) -> None:
    """Remove the user from every supplementary group.

    Enumerates what the user is ACTUALLY in rather than subtracting a fixed
    list, so a group nobody thought of (lxd, disk, shadow) is still removed.
    """
    out = _run(["id", "-nG", user], check=False).stdout or ""
    primary = (_run(["id", "-ng", user], check=False).stdout or "").strip()
    for group in out.split():
        if group == primary or group in ALLOWED_SUPPLEMENTARY_GROUPS:
            continue
        _run(["gpasswd", "-d", user, group], check=False)


def _assert_unprivileged(user: str) -> None:
    """Refuse to finish if the user still has a route to privilege.

    Verifying the end state beats trusting the steps that produced it: this is
    the check that would have caught a stale sudoers entry or a group the
    stripping missed.
    """
    groups = (_run(["id", "-nG", user], check=False).stdout or "").split()
    primary = (_run(["id", "-ng", user], check=False).stdout or "").strip()
    extra = [g for g in groups
             if g != primary and g not in ALLOWED_SUPPLEMENTARY_GROUPS]
    if extra:
        raise ProvisionError(
            f"{user} is still in supplementary groups {extra}; refusing to "
            f"present it as a restricted user"
        )

    sudo_check = _run(["sudo", "-n", "-l", "-U", user], check=False)
    listing = (sudo_check.stdout or "")
    if "not allowed to run sudo" not in listing and "may run" in listing:
        raise ProvisionError(
            f"{user} has sudo privileges according to `sudo -l -U {user}`; "
            f"refusing to present it as a restricted user"
        )


def _run(argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise ProvisionError(f"{' '.join(argv)} failed: {result.stderr.strip()}")
    return result


def editor_state_root(user: str) -> str:
    """Root of the project user's private code-server state.

    MUST stay in step with code_server.cfg_dir_for(), which passes a subdirectory
    of this as --user-data-dir. code-server does NOT create the parents of that
    flag: it warns "Could not create socket ..." and runs degraded with an
    unusable extensions dir. Tests assert the two agree, because the drift
    failure is silent — the editor still starts and still serves.
    """
    import pwd
    try:
        home = pwd.getpwnam(user).pw_dir
    except KeyError:
        home = os.path.join("/home", user)
    return os.path.join(home, ".orchestratia", "code-server")


def _ensure_editor_state_dir(user: str) -> None:
    """Create it as root and hand it to the project user.

    Neither the daemon (home is 0750, owned by the project user) nor a sudo call
    can do this: the tier sudoers rule is deliberately only tmux/git/code-server,
    and widening it for a mkdir would trade a real boundary for a convenience.
    Provisioning already runs as root, so it belongs here.
    """
    root = editor_state_root(user)
    os.makedirs(root, exist_ok=True)
    parent = os.path.dirname(root)
    _run(["chown", "-R", f"{user}:{user}", parent])
    os.chmod(root, 0o700)
    print(f"  editor state dir {root}")


# Run as the project user by _write_editor_settings: merge the forced keys into the
# locked-down editor's settings, keeping the user's own.
_WRITE_SETTINGS = """\
import json, os, sys
path, forced = sys.argv[1], json.loads(sys.argv[2])
try:
    with open(path) as f:
        data = json.load(f)
    data = data if isinstance(data, dict) else {}
except (OSError, ValueError):
    data = {}
data.update(forced)
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.replace(tmp, path)
"""


def _write_editor_settings(user: str, project_id: str) -> None:
    """Point the locked-down editor's terminal at the Orchestratia session picker.

    Nothing else can: the daemon cannot write into the project user's home, and the
    tier sudoers rule stays tmux/git/code-server. Without this the editor's terminal was
    a plain shell, outside the recorded sessions. Written AS the project user, never as
    root: the directory is theirs, so a root write could be redirected through a symlink
    they planted. The user may change these settings — they are a default, not a control.
    """
    import json
    import sys
    from orchestratia_agent import code_server as cs
    path = os.path.join(cs.cfg_dir_for(user, project_id), "User", "settings.json")
    result = subprocess.run(
        [sys.executable, "-c", _WRITE_SETTINGS, path, json.dumps(cs.settings_json("restricted"))],
        user=user, group=user, extra_groups=[], cwd="/", capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise ProvisionError(f"could not write the editor settings for {user}: {result.stderr.strip()}")
    print(f"  editor settings {path}")


def provision(project_id: str, workspaces: list[str],
              daemon_user: str, config_path: str,
              code_server_path: str | None = None) -> int:
    """Provision ONE project's restricted user. Additive, idempotent. Root only.

    Derives the OS user deterministically from project_id, refuses a hash
    collision with a different project, applies workspace ACLs, and rewrites the
    sudoers drop-in from ALL provisioned projects (so an existing project's rule
    survives a new project being added). Merges — never replaces — the projects map,
    and adds to (never replaces) the project's workspaces: see merge_project_workspaces.
    """
    if os.geteuid() != 0:
        raise ProvisionError("provision-tier must be run as root (use sudo)")

    from orchestratia_agent.privilege import project_username
    user = project_username(project_id)          # validates the project_id shape
    validate_username(user)                       # and the derived username

    if daemon_user == "root":
        # Reachable from a plain root shell, where $SUDO_USER is unset. The
        # generic validator would say "'root' is not a restricted user", which
        # names the wrong role and sends the operator looking in the wrong place.
        raise ProvisionError(
            "--daemon-user is required when running from a root shell "
            "(there is no $SUDO_USER to infer it from). Pass the user the "
            "agent daemon runs as, e.g. --daemon-user ubuntu"
        )
    daemon_user = validate_username(daemon_user)
    spaces = [validate_workspace(w) for w in workspaces]
    if not spaces:
        raise ProvisionError("at least one --workspace is required")
    for w in spaces:
        if not os.path.isdir(w):
            raise ProvisionError(f"workspace {w} does not exist")

    tmux_path = shutil.which("tmux")
    if not tmux_path:
        raise ProvisionError("tmux not found; the restricted tier requires it")
    git_path = shutil.which("git")
    if not git_path:
        raise ProvisionError("git not found; the restricted tier requires it")
    # code-server is OPTIONAL: if present (or explicitly given) the editor is
    # enabled for this box's projects; if absent, the tier is tmux+git only and
    # no editor is advertised.
    cs_path = code_server_path or shutil.which("code-server")
    if not shutil.which("setfacl"):
        raise ProvisionError(
            "setfacl not found; install the 'acl' package "
            "(apt install acl / brew install acl)"
        )

    # Load the config FIRST: everything below either validates against it
    # (collision guard) or merges into it, and a read error must abort before we
    # create a user or touch anyone's filesystem — not leave a half-provisioned box.
    from orchestratia_agent.config import load_config, save_config
    try:
        existing_cfg = load_config(config_path) or {}
    except FileNotFoundError:
        existing_cfg = {}
    except Exception as e:  # noqa: BLE001
        raise ProvisionError(f"cannot read config {config_path}: {e}") from e

    priv = dict(existing_cfg.get("privilege") or {})
    existing_projects = dict(priv.get("projects") or {})
    assert_no_collision(user, project_id, existing_projects)

    # Merge this project in, then build ALL sudoers lines. Validating the whole
    # set now means bad input fails before any user/ACL/file change.
    merged_projects = merge_project_workspaces(existing_projects, project_id, user, spaces)
    lines = sudoers_lines(daemon_user, merged_projects, tmux_path, git_path,
                          code_server_path=cs_path)

    # 1. The user: no login password, and explicitly none of the escalation groups.
    if _run(["id", user], check=False).returncode != 0:
        _run(["useradd", "-m", "-s", "/bin/bash",
              "--comment", f"Orchestratia restricted agent (project {project_id})", user])
        print(f"  created user {user}")
    else:
        print(f"  user {user} already exists — converging")
    _run(["passwd", "-l", user], check=False)
    _strip_supplementary_groups(user)
    _assert_unprivileged(user)
    _ensure_editor_state_dir(user)
    if cs_path:
        _write_editor_settings(user, project_id)

    # 2. Workspace ACLs for THIS project's workspaces.
    home_roots = [h for h in ("/home", "/Users") if os.path.isdir(h)]
    for w in spaces:
        for cmd in acl_commands(user, w):
            _run(cmd)
        # Close the cross-tenant read: a sibling project's user has --x on the
        # shared parent, so a world-readable workspace would otherwise be
        # readable across tenants. Remove 'other' access on the workspace root.
        _run(workspace_lockdown_command(w))
        print(f"  granted {w} (world access removed)")
        if any(_is_within(w, h) for h in home_roots):
            print(
                f"    WARNING: {w} is inside a user home. Traversing to it "
                f"exposes world-readable files in that home (~/.bashrc, "
                f"~/.gitconfig, parts of ~/.claude) to {user}. Mode-0600 files "
                f"stay protected. Prefer a workspace outside /home."
            )

    # 3. Sudoers drop-in (all projects), validated before it goes live.
    tmp = "/etc/sudoers.d/.orchestratia-agent-tiers.tmp"
    final = "/etc/sudoers.d/orchestratia-agent-tiers"
    with open(tmp, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o440)
    check = _run(["visudo", "-cf", tmp], check=False)
    if check.returncode != 0:
        os.unlink(tmp)
        raise ProvisionError(
            f"refusing to install invalid sudoers: {check.stderr.strip()}"
        )
    os.replace(tmp, final)

    # 4. Config: merge this project into the projects map, pin both binaries.
    cfg = existing_cfg
    priv["projects"] = merged_projects
    priv["tmux_path"] = tmux_path
    priv["git_path"] = git_path
    if cs_path:
        priv["code_server_path"] = cs_path      # enables the editor capability
    priv.pop("restricted_user", None)   # drop any legacy flat keys once migrated
    priv.pop("workspaces", None)
    cfg["privilege"] = priv
    save_config(config_path, cfg)

    print(f"\n  Project:            {project_id}")
    print(f"  Restricted user:    {user}")
    print(f"  Workspaces granted: {', '.join(merged_projects[project_id]['workspaces'])}")
    print(f"  Projects on this box: {', '.join(merged_projects)}")
    print("\n  NEXT — authenticate your agent tooling once, as that user:")
    print(f"      sudo -iu {user}")
    print("      claude login      # or: gemini auth / codex login")
    print("\n  Then restart the daemon:")
    print("      sudo systemctl restart orchestratia-agent\n")
    return 0


def revoke(project_id: str, workspaces: list[str], config_path: str) -> int:
    """Take workspace grants away from ONE project's restricted user. Root only.

    Removes the ACLs, re-applies what the project keeps, verifies the result with
    getfacl rather than trusting setfacl's exit code, then drops the record. A path
    the config does not list is still cleaned: that is exactly the grant that was
    left behind when re-provisioning used to replace the list.
    """
    if os.geteuid() != 0:
        raise ProvisionError("provision-tier must be run as root (use sudo)")
    from orchestratia_agent.privilege import project_username
    user = validate_username(project_username(project_id))
    if not workspaces:
        raise ProvisionError("at least one --revoke-workspace is required")
    if not shutil.which("setfacl") or not shutil.which("getfacl"):
        raise ProvisionError("setfacl/getfacl not found; install the 'acl' package")

    from orchestratia_agent.config import load_config, save_config
    try:
        cfg = load_config(config_path) or {}
    except Exception as e:  # noqa: BLE001
        raise ProvisionError(f"cannot read config {config_path}: {e}") from e
    priv = dict(cfg.get("privilege") or {})
    projects = dict(priv.get("projects") or {})
    spec = dict(projects.get(project_id) or {})
    if not spec:
        raise ProvisionError(f"project {project_id} has no restricted tier on this box")

    recorded = list(spec.get("workspaces") or [])
    targets = [_normalise_for_revoke(w) for w in workspaces]
    remaining = [w for w in recorded if w not in targets]
    plans = [(t, revoke_commands(user, t, remaining)) for t in targets]   # all refusals first

    for target, cmds in plans:
        for cmd in cmds:
            if "-x" in cmd and not os.path.lexists(cmd[-1]):
                continue                      # a folder deleted since it was granted
            _run(cmd)
        if os.path.lexists(target):
            perms = _acl_perms(_run(["getfacl", "-p", target]).stdout or "", user)
            # Traverse is still expected when a kept workspace lies inside the target.
            needs_traverse = any(_is_within(w, target) for w in remaining)
            if perms is not None and not (needs_traverse and perms == "--x"):
                raise ProvisionError(f"{target} still grants {user} {perms} after the revoke")
        note = "" if target in recorded else " (not in the config — cleared anyway)"
        print(f"  revoked {target}{note}")
        if os.path.lexists(target):
            print(f"    world access on {target} stays removed; restore it with chmod o+rX if needed")

    spec["workspaces"] = remaining
    projects[project_id] = spec
    priv["projects"] = projects
    cfg["privilege"] = priv
    save_config(config_path, cfg)
    print(f"\n  Project:            {project_id}")
    print(f"  Restricted user:    {user}")
    print(f"  Workspaces granted: {', '.join(remaining) or '(none)'}")
    print("\n  Then restart the daemon:")
    print("      sudo systemctl restart orchestratia-agent\n")
    return 0

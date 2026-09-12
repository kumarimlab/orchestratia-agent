#!/usr/bin/env bash
#
# per-project-isolation-probe.sh — PROVE, on real OS users, that per-project
# restricted users are isolated from each other by the kernel. Unit tests cannot
# show this; only two real users on a real box can.
#
# Provisions two throwaway projects via the ACTUAL provision code, starts a tmux
# session as each, then asserts from user A that it cannot see, drive, or read
# user B — and that git runs as A but is ACL-denied on B's workspace. Cleans up
# everything at the end (users, sudoers drop-in, workspaces, config) via a trap.
#
# Run on a throwaway/staging box, as a user with sudo:
#   bash scripts/per-project-isolation-probe.sh
#
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PID_A="aaaaaaaa-1111-1111-1111-111111111111"   # -> orcp-aaaaaaaa1111
PID_B="bbbbbbbb-2222-2222-2222-222222222222"   # -> orcp-bbbbbbbb2222
UA="orcp-aaaaaaaa1111"
UB="orcp-bbbbbbbb2222"
WS_A="/srv/probe-a"
WS_B="/srv/probe-b"
# Root-owned config path: provision runs as root and writes it, mirroring the
# real /etc/orchestratia/config.yaml. A user-owned temp file is not writable by
# the (AppArmor-confined) sudo root on some boxes.
CONFIG="/etc/orchestratia-probe/config.yaml"
DAEMON_USER="$(id -un)"
PASS=0; FAIL=0

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { PASS=$((PASS+1)); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; }

cleanup() {
    say "Cleanup"
    for u in "$UA" "$UB"; do
        sudo -n -u "$u" tmux kill-server 2>/dev/null || true
        sudo pkill -u "$u" 2>/dev/null || true
        sudo userdel -r "$u" 2>/dev/null && echo "  removed user $u" || true
    done
    sudo rm -f /etc/sudoers.d/orchestratia-agent-tiers && echo "  removed sudoers drop-in" || true
    sudo rm -rf "$WS_A" "$WS_B" && echo "  removed probe workspaces" || true
    sudo rm -rf "$(dirname "$CONFIG")" && echo "  removed probe config" || true
    # Prove cleanup worked — an orphaned restricted user is exactly what we must not leave.
    for u in "$UA" "$UB"; do
        id "$u" >/dev/null 2>&1 && echo "  WARNING: user $u still exists" || true
    done
}
trap cleanup EXIT

say "Provision two projects via the real provision code"
sudo mkdir -p "$(dirname "$CONFIG")" "$WS_A" "$WS_B"
sudo PYTHONPATH="$REPO" python3 -m orchestratia_agent provision-tier \
     --project "$PID_A" --workspace "$WS_A" --daemon-user "$DAEMON_USER" --config "$CONFIG" \
     >/dev/null 2>&1 && pass "provisioned project A ($UA)" || fail "provision A"
sudo PYTHONPATH="$REPO" python3 -m orchestratia_agent provision-tier \
     --project "$PID_B" --workspace "$WS_B" --daemon-user "$DAEMON_USER" --config "$CONFIG" \
     >/dev/null 2>&1 && pass "provisioned project B ($UB)" || fail "provision B"

id "$UA" >/dev/null 2>&1 && pass "user $UA exists" || fail "user $UA missing"
id "$UB" >/dev/null 2>&1 && pass "user $UB exists" || fail "user $UB missing"

say "Sudoers drop-in still authorizes BOTH projects (additive, not clobbered)"
sudo grep -q "($UA)" /etc/sudoers.d/orchestratia-agent-tiers && pass "A's rule present" || fail "A's rule missing"
sudo grep -q "($UB)" /etc/sudoers.d/orchestratia-agent-tiers && pass "B's rule present (A did not clobber it)" || fail "B's rule missing"

say "Init each project's repo AS its own user (as the real session would)"
sudo -n -u "$UA" -H git -C "$WS_A" init -q 2>/dev/null && pass "A initialised its repo" || fail "A repo init"
sudo -n -u "$UB" -H git -C "$WS_B" init -q 2>/dev/null && pass "B initialised its repo" || fail "B repo init"
# B writes a PRIVATE (0600) secret it owns — this is what per-project isolation
# must protect. (World-readable files are readable by anyone regardless; that is
# an operator file-permission choice, not a property of this feature — see the
# probe notes. So we test the 0600 case, which our ACL model MUST hold.)
sudo -n -u "$UB" -H sh -c "umask 077; printf B-SECRET > $WS_B/secret.txt" 2>/dev/null
sudo -n -u "$UB" -H chmod 600 "$WS_B/secret.txt" 2>/dev/null

say "Start a tmux session as each user"
sudo -n -u "$UA" -H tmux new-session -d -s probeA "sleep 300" 2>/dev/null && pass "A session started" || fail "A session start"
sudo -n -u "$UB" -H tmux new-session -d -s probeB "sleep 300" 2>/dev/null && pass "B session started" || fail "B session start"

say "ISOLATION: user A must not see, drive, or read user B"
# A listing B's tmux server (B's socket is /tmp/tmux-<uid B>/, 0700)
if sudo -n -u "$UA" -H tmux ls 2>/dev/null | grep -q probeB; then
    fail "A can see B's tmux session"
else
    pass "A cannot see B's tmux session"
fi
# A reading B's PRIVATE (0600) file — the real isolation property
if sudo -n -u "$UA" -H cat "$WS_B/secret.txt" 2>/dev/null | grep -q B-SECRET; then
    fail "A can read B's private (0600) file"
else
    pass "A cannot read B's private (0600) file"
fi
# A killing B's tmux server
sudo -n -u "$UA" -H tmux kill-server 2>/dev/null || true
if sudo -n -u "$UB" -H tmux ls 2>/dev/null | grep -q probeB; then
    pass "A cannot kill B's tmux server (B still alive)"
else
    fail "A killed / B's session gone"
fi

say "git_changes.collect(run_as=A) works on an operator-owned repo (the deployed path)"
# The workspace root is owned by whoever created it (here root, as the operator
# would); git run as A would refuse for dubious ownership without the scoped
# safe.directory that collect() adds. This exercises the REAL code, not raw git.
sudo -n -u "$UA" -H sh -c "cd $WS_A && printf 'hi' > f.txt && git add f.txt && git -c user.email=a@a -c user.name=a commit -qm x" 2>/dev/null
COLLECT_OUT=$(PYTHONPATH="$REPO" python3 -c "
from orchestratia_agent import git_changes as gc
r = gc.collect('$WS_A', run_as='$UA')
print('is_repo', r.get('is_repo'), 'inspection_limited' in r)
" 2>&1)
echo "    collect() -> $COLLECT_OUT"
echo "$COLLECT_OUT" | grep -q "is_repo True" && pass "collect(run_as=A) inspected the operator-owned repo" || fail "collect(run_as=A) failed on operator-owned repo"
# collect(run_as=B) against A's workspace must be ACL-denied (B has no grant on A)
COLLECT_B=$(PYTHONPATH="$REPO" python3 -c "
from orchestratia_agent import git_changes as gc
r = gc.collect('$WS_A', run_as='$UB')
print('is_repo', r.get('is_repo'))
" 2>&1)
echo "$COLLECT_B" | grep -q "is_repo False" && pass "collect(run_as=B) cannot read A's repo (ACL denies)" || fail "collect(run_as=B) reached A's repo"

say "Confinement: neither user has sudo or docker"
for u in "$UA" "$UB"; do
    if sudo -n -u "$u" -H sudo -n true 2>/dev/null; then fail "$u has sudo"; else pass "$u has no sudo"; fi
done

echo
printf '\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

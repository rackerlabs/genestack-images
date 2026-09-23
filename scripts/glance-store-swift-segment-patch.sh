#!/bin/bash
# Fix final-segment Content-Length in the glance_store Swift driver.
#
# Context: glance_store LP#2136857 ("Size mismatch in swift driver", Fix
# Released) refactored the segmented-upload size handling in 5.x. That refactor
# REMOVED the per-segment size adjustment (`chunk_size = left`) that older
# versions (4.9.1) had, and added total-size validation blocks instead. As a
# side effect, the final PARTIAL segment is now PUT with
# content_length = large_object_chunk_size (full chunk) while the reader only
# delivers the true remainder. Swift waits for the missing bytes until
# client_timeout, then returns 499/ChunkReadTimeout -> any image large enough
# to be segmented fails to upload. (This matches LP#2136857's own "test case 2:
# declared > actual -> times out then 409" description.)
#
# This patch RESTORES the per-segment `chunk_size = left` adjustment. It is
# COMPATIBLE with the LP#2136857 total-size validation blocks (Size exceeds /
# Size mismatch): those validate combined_chunks_size vs image_size and still
# fire on a genuine client size mismatch. We only touch the
# `else: content_length = chunk_size` block; all validation blocks are left intact.
#
# NOTE: If the running glance_store version is NEWER than 5.4.0 and already
# ships a complete LP#2136857 fix that handles the final partial segment, this
# script is a no-op (its guard checks for the shrink logic first). Prefer moving
# to a glance_store release that fixes this upstream over carrying this patch.
#
# Idempotent: no-op if already patched. Fails the build if the expected block
# is not found (base changed) so we never ship a silently-unpatched image.
set -euo pipefail

STORE_PY="$(find /var/lib/openstack \
   -path '*/glance_store/_drivers/swift/store.py' \
   -print -quit)"
if [[ -z "${STORE_PY}" || ! -f "${STORE_PY}" ]]; then
  echo "ERROR: glance_store swift store.py not found" >&2
  exit 1
fi
echo "Patching: ${STORE_PY}"

/var/lib/openstack/bin/python3 - "$STORE_PY" <<'PYEOF'
import sys, re, py_compile
p = sys.argv[1]
src = open(p).read()

# Already patched?  (idempotent no-op)
if "chunk_size > left" in src:
    print("glance_store swift segment fix already present; skipping.")
    sys.exit(0)

# Whitespace-robust match: find the segmented-upload else-branch
#     else:
#         content_length = chunk_size
# capturing the actual indentation so we preserve it exactly. Tolerates any
# indentation width and optional blank lines between the two statements.
pat = re.compile(
    r'(?P<i_else>[ \t]+)else:[ \t]*\n'
    r'(?:[ \t]*\n)*'
    r'(?P<i_body>[ \t]+)content_length = chunk_size[ \t]*\n'
)

# Keep only the match whose body sits in a segmented-upload context (guard
# against unrelated 'else:' blocks). The real one is preceded not far above by
# 'chunk_size = self.large_object_chunk_size'.
target = None
for m in pat.finditer(src):
    preceding = src[max(0, m.start() - 400):m.start()]
    if "chunk_size = self.large_object_chunk_size" in preceding:
        target = m
        break

if target is None:
    sys.stderr.write(
        "ERROR: could not locate the segmented-upload 'else: content_length = "
        "chunk_size' block in " + p + " -- glance_store may have changed; "
        "refusing to ship unpatched.\n")
    sys.exit(1)

i_else = target.group("i_else")   # indentation of 'else:'
i_body = target.group("i_body")   # indentation of the body statement
step = i_body[len(i_else):]       # one indent level
inner = i_body + step             # indentation for nested if-bodies

replacement = (
    i_else + "else:\n"
    + i_body + "left = image_size - combined_chunks_size\n"
    + i_body + "if left == 0:\n"
    + inner + "break\n"
    + i_body + "if chunk_size > left:\n"
    + inner + "chunk_size = left\n"
    + i_body + "content_length = chunk_size\n"
)

src = src[:target.start()] + replacement + src[target.end():]
open(p, "w").write(src)
py_compile.compile(p, doraise=True)
print("Applied glance_store swift final-segment content_length fix.")
PYEOF

echo "glance_store swift segment patch complete."

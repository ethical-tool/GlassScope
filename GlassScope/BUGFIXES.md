# Upstream REA CLI — verified bug fixes

GlassScope was rebuilt from the REA (*Reverse Engineer Anything*, morluto/rea)
codebase. During the audit of the CLI hot paths, four real bugs were verified
by tracing the full code path, then fixed. The fixes are shipped both as
patched source and as a unified diff: `patches/rea-bugfixes.patch`.

## 1. `--filter-output` slice with a missing/empty bound silently returned empty output

**File:** `src/cli/outputFilter.ts` (parser), surfaced through
`src/cliOutput.ts` validation messaging.

**Before:** the slice grammar `[start,end]` refused 3+ bounds
(`extra_slice_bounds`) but silently accepted 0 or 1 bounds. `items[5]`,
`items[5,]`, `items[,3]` and `items[]` collapsed into `NaN`/`0` bounds, the
selection loop never ran, and the CLI printed an **empty result with exit
code 0** — silent data loss on a standard slice spelling
(`results[3,]` = "rest of array").

**After:** malformed slices (missing or empty bounds) are refused with the
same mechanism as extra bounds. New error kind `missing_slice_bounds` with a
matching, user-facing message: *"The --filter-output expression has a slice
with a missing or empty bound. Use [start,end]."*

## 2. `--no-<flag>` was accepted for every option, producing misleading validation errors

**File:** `src/cli/argvParser.ts`.

**Before:** the negation branch skipped the boolean check every other binding
path performs and stored a non-string `false`. For a number/string/array
option, `rea <cmd> --no-limit` failed later with *"expected number, received
boolean"* instead of the correct *"Unknown flag"* refusal.

**After:** `--no-<x>` is rejected up front unless `<x>` is declared boolean:
`rea <cmd> --no-limit` → `Unknown flag: --no-limit`.

## 3. `rea -v` could never print the version (dead guard in the one-shot launcher)

**Files:** `src/cliBuiltinArguments.ts`, `src/cliOneShot.ts`.

**Before:** `cliOneShot` guarded a `global.flags.has("-v")` check, but the
global-argument parser only put `--version` (special-cased) and members of
`CLI_BUILTIN_FLAGS` into `flags` — `-v` was never added anywhere. So `rea -v`
fell through to an unknown-command error with exit 1. The alias was silently
broken and the guard was dead code.

**After:** a bare `-v` (with no following value) is normalized into
`flags` as `--version` in `parseCliGlobalArguments`, so every consumer reads
it uniformly and `rea -v` prints the version. The dead `-v` check in
`cliOneShot` was removed.

## 4. A missing file whose name begins with `{` or `[` was mislabeled "invalid JSON"

**File:** `src/cli/cliJsonInput.ts`.

**Before:** when inline JSON parsing failed and the file read failed with
`ENOENT`/`ENAMETOOLONG`/`ENOTDIR`, any argument starting with `{`/`[` without
a `.json` extension was reported as `invalid_format: expected JSON` — even
when it was a mistyped path. On Linux, `{` and `[` are legal filename
characters, so passing a real (but missing) path like `./{data}` never told
the user the file was not found; the read-failure diagnostic naming the path
and system code was unreachable for this input class.

**After:** the "inline JSON" interpretation is taken only when the value
could actually start a JSON document (`{` followed by a quoted key, or `[`).
`{data}` and similar are reported as the file-read failure they are — with
the path and system error code — instead of a misleading JSON error.

---

All four fixes were typechecked against the full repository (strict,
`noUncheckedIndexedAccess`, `verbatimModuleSyntax`) with no new errors.

Verification of fix 1 (parser behavior), run against the patched source:

| Input | Before | After |
| --- | --- | --- |
| `items[0,2]` | slice 0..2 | slice 0..2 (unchanged) |
| `items[5]` | empty output, exit 0 | refused: missing/empty bound |
| `items[5,]` | empty output, exit 0 | refused: missing/empty bound |
| `items[]` | empty output, exit 0 | refused: missing/empty bound |
| `items[1,2,3]` | refused (extra bounds) | refused (unchanged) |

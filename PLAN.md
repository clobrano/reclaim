# reclaim — Implementation Plan

Companion to the feature list (Oct 19, 2026). Numbers like **F5** refer to the
features in that list.

## Guiding decisions

- **Read-only before acting.** The first milestones only observe and suggest
  commands. Direct actions come after protection and confirmation are in place.
- **No estimate relies on RSS.** Freed-memory estimates come from
  `smaps_rollup` (USS, PSS, SwapPss). When those can't be read, the tool shows
  `?` and doesn't guess.
- **Re-check at action time.** The snapshot the user looked at is stale by the
  time they confirm. Actions re-read `cgroup.procs` and refer to processes by
  pidfd, so a reused PID never receives a signal.
- **Linux only, cgroup v2 first.** On hosts without a unified hierarchy, views
  that depend on cgroups fall back to the process tree.

## Stack

| Concern | Choice |
|---|---|
| TUI | `charmbracelet/bubbletea`, `bubbles` (table, viewport, textinput), `lipgloss` |
| Config | TOML via `BurntSushi/toml` |
| Syscalls | `golang.org/x/sys/unix` (`pidfd_open`, `pidfd_send_signal`) |
| Tests | stdlib `testing`, fixture trees, `teatest` for UI goldens |
| Release | `goreleaser`, static binary (`CGO_ENABLED=0`) |

Minimum kernel: 5.3 (pidfd), PSI enabled (`CONFIG_PSI`, sometimes `psi=1`).
Optional: 5.14 for `cgroup.kill`. Each missing feature is detected at startup
and the feature that needs it is disabled with a visible note.

## Package layout

```
cmd/reclaim/            main, flags, --dump (JSON snapshot, headless), --helper (sudo path)
internal/procfs/        /proc parsing: stat, status, cmdline, exe, cgroup, smaps_rollup,
                        meminfo, vmstat, swaps, pressure/memory; root path injectable
internal/cgroupfs/      /sys/fs/cgroup walk: memory.current, memory.stat, memory.swap.current,
                        memory.pressure, cgroup.procs, cgroup.freeze, cgroup.events, cgroup.kill
internal/sample/        Sampler: periodic snapshot, bounded worker pool, per-PID cache
internal/model/         Process, Group, Snapshot, MemStats (USS/PSS/Shared/Swap/SwapPss/RSS)
internal/group/         Grouper interface + three implementations (F1)
internal/detect/        cgroup-path classifiers: systemd units, podman/docker/containerd/cri-o,
                        kubepods, kind nodes, libvirt/qemu machines; runtime availability
internal/sysmem/        system breakdown + reclaimability tags (F3)
internal/history/       per-group ring buffers (memory, PSI totals) over the session
internal/pressure/      PSI parsing, culprit scoring (F4)
internal/protect/       config load, default protected set, matchers (F8)
internal/action/        estimate, warnings, terminate, freeze/thaw, frozen registry (F5–F7)
internal/suggest/       command builders + shell quoting (F9–F11)
internal/clipboard/     OSC 52 with tmux/screen passthrough (F12)
internal/ui/            bubbletea model: views, panels, dialogs, keymap
```

Everything under `procfs`/`cgroupfs` takes a root `fs.FS` (or a base path), so
tests run against fixture trees in `testdata/` with no special privileges.

## Data layer

### Per-process accounting (F2)

From `/proc/<pid>/smaps_rollup`:

- **USS** = `Private_Clean + Private_Dirty`
- **PSS** = `Pss`
- **Shared** = `Shared_Clean + Shared_Dirty`
- **Swap** = `Swap`, plus `SwapPss` for the proportional share
- **RSS** comes from the same file and is shown only as a familiar reference.

Kernel threads (empty `cmdline`, `PF_KTHREAD`) are excluded.

**Cost.** Reading `smaps_rollup` walks page tables, which is expensive for
large processes. Defaults: 2 s refresh, a worker pool sized to `GOMAXPROCS`, and
a per-PID cache keyed on `(pid, starttime)`. Small or idle processes are
refreshed less often, based on `utime+stime` and `VmRSS` deltas from the cheap
`stat`/`status` reads.

**Permission.** Reading another user's `smaps_rollup` fails with `EACCES`
because it needs ptrace-read access. Those processes still show `VmRSS` from
`status`. Their USS/PSS show as `?`, and a header badge says "N processes not
readable — run with sudo to see them". This covers the degraded half of F7.

### Group accounting

A group's numbers are the sums over its members. The freed-memory estimate is a
range, never a single number:

- **Lower bound** = Σ USS + Σ SwapPss. This is what F6 calls "USS plus private
  swap". The kernel doesn't expose private swap directly, so SwapPss is the
  closest available proxy, and the UI says so in the dialog's detail line.
- **Upper bound** = Σ PSS + Σ SwapPss. Pages shared only among the group's own
  members (a browser's renderers, for example) are freed when the whole group
  goes. Σ USS misses them, but they fall within Σ PSS.

When a group is a cgroup, `memory.current` and `memory.stat` (`anon`, `file`,
`shmem`, `kernel`) are shown alongside. The dialog states that **page cache
charged to the cgroup is not freed by killing it**, because it is reparented and
reclaimed later by the kernel.

### System breakdown (F3)

Read from `/proc/meminfo`, `/proc/swaps` and `/sys/block/zram*/mm_stat`. Each
row gets one tag:

| Category | Source | Tag |
|---|---|---|
| Anonymous | `AnonPages` | freeable by an action |
| Page cache (clean) | `Cached + Buffers − Shmem − Dirty` | the kernel frees this itself |
| Dirty / writeback | `Dirty + Writeback` | the kernel frees this itself (after writeback) |
| Slab, reclaimable | `SReclaimable` | the kernel frees this itself |
| Slab, unreclaimable | `SUnreclaim` | not reclaimable |
| Shmem / tmpfs | `Shmem` | freeable by an action (remove files, stop owner) |
| Swap used | `SwapTotal − SwapFree` | freeable by an action (swap flush, F11) |
| zram footprint | `mm_stat` `mem_used_total` | not reclaimable (shrinks as swap empties) |
| Hugepages (reserved) | `HugePages_Total × Hugepagesize` | not reclaimable (config change) |
| Kernel: page tables, stacks, vmalloc, percpu | `PageTables`, `KernelStack`, … | not reclaimable |
| Unaccounted | `MemTotal − MemFree − Σ above` | not reclaimable |

Each row has a one-line plain explanation, and a longer one opens with `?`.
These strings live in one table in `sysmem`, so the wording is reviewed in one
place.

### Pressure and culprit (F4)

- System: `/proc/pressure/memory` `some`/`full`, `avg10`/`avg60`, and `total`.
- Per group: the cgroup's `memory.pressure`. Process-tree groups that have no
  cgroup of their own inherit their cgroup's PSI, which is marked as shared.
- PSI measures who is **stalled**, which is not necessarily who is **causing**
  the stall. The culprit score combines both signals over a sliding window
  (default 60 s), using `history`:
  - the group's share of Δ PSI `total` among leaf cgroups (who suffers)
  - the group's Δ (USS + swap) in bytes, normalized against the system-wide
    Δ anon (who grew)
  - `score = 0.4·psi_share + 0.6·growth_share`. Weights are configurable.
- A culprit is flagged only while system `some avg10` exceeds a threshold
  (default 10%). The flag has to hold for two consecutive samples to avoid
  flapping. The flag shows the evidence, for example "grew 900 MB in 60 s, 35%
  of stall time".

## Grouping views (F1)

All three implement `Grouper.Group(snapshot) []*Group`. A group can have
children, so the UI renders a collapsible tree. One key (`v`) cycles the views,
and expansion state is kept per view.

1. **App / scope.** Uses the cgroup v2 path. systemd unit names are parsed and
   unescaped (`\x2d`): `app-gnome-code-4711.scope` → "code",
   `app-org.gnome.Terminal.slice` → "Terminal", and `session-3.scope` and
   `*.service` keep their unit names. Processes in a catch-all scope are split
   into sub-groups by top-level process subtree. Hosts without systemd fall back
   to view 3.
2. **Container / pod / VM.** Classified by `detect` from cgroup path patterns:
   - `libpod-<id>.scope` (podman, rootful or rootless under `user@UID.service`)
   - `docker-<id>.scope`, `cri-containerd-<id>.scope`, `crio-<id>.scope`
   - `kubepods*/…pod<uid>.slice`, which become pod groups
   - kind: a node is a podman/docker container named `<cluster>-control-plane`
     or `-worker*`. Its nested `kubepods` sit under its cgroup, so the result is
     **cluster → node → pod → container**.
   - `machine-qemu\x2d<n>\x2d<name>.scope` (libvirt). `machine.slice` means
     `qemu:///system`, and a user slice means `qemu:///session`.

   IDs are resolved to names with optional, read-only queries
   (`podman ps --format json`, `docker ps`, `kubectl get pods -A -o json`,
   `virsh list`), cached and refreshed every 30 s. If a query fails, the short
   ID is shown. Everything not matched goes under "Host".
3. **Process tree.** Built from the ppid tree. Top-level groups are the children
   of the session leader or of `systemd --user`, and a subtree is expandable to
   single processes.

## Acting directly (F5–F8)

Direct actions apply **only** to process groups (views 1 and 3, plus the Host
part of view 2). On a container, pod or VM, the action keys open the suggestion
panel (F9–F10) instead.

### Flow

`t`/`f` on a group → `action.Plan(group)` → confirmation dialog → `action.Execute(plan)`

`Plan` re-reads membership, opens a **pidfd for every PID**, and records
`(pid, starttime)`. It also computes the estimate range and collects warnings:

- the group is protected → needs an override (see below)
- the group is an ancestor of reclaim ("this is your terminal's parent")
- processes owned by other users → sudo will be used
- a systemd unit with `Restart=` set → "systemd will restart it; consider
  `systemctl [--user] stop <unit>`", with a copy button
- most memory is shared outside the group → small lower bound, explained
- page cache charged to the cgroup is not freed (cgroup groups)
- freeze: "freezing frees no RAM by itself; it lets the kernel swap these pages
  out under pressure", plus a note if swap is off or nearly full

The dialog shows the estimate range, the PIDs (first 10 with comm, then "+N
more", expandable) and the warnings. It defaults to **Cancel**.

### Terminate (F5)

1. `pidfd_send_signal(SIGTERM)` to each process.
2. Poll the pidfds for exit, up to the grace period (`grace = "5s"` in config,
   adjustable in the dialog).
3. Survivors get SIGKILL. For a cgroup that only holds this group, write
   `cgroup.kill` when available. That catches processes forked during the grace
   period.
4. Report: which processes exited and which were killed, and the actual Δ
   `MemAvailable` next to the estimate. Showing the real figure keeps the
   estimate honest over time.

### Freeze / resume (F5)

- For a cgroup group whose `cgroup.freeze` is writable (user-delegated systemd
  scopes are), write `1` and wait for `frozen 1` in `cgroup.events`.
- Otherwise, SIGSTOP each process via pidfd. The dialog notes that a parent
  shell may report the job as stopped.
- Frozen groups go into a **Frozen** list with a resume key (`r`). The registry
  is persisted to `$XDG_STATE_HOME/reclaim/frozen.json`, so frozen groups are
  never orphaned invisibly. On startup, reclaim reconciles the registry with the
  real state. On quit with frozen groups, it asks: resume all, keep, or cancel.

### Least privilege (F7)

- The TUI always runs as the invoking user. If started as root, it warns and
  asks for confirmation.
- Acting on another user's processes suspends the TUI (`tea.ExecProcess`) and
  runs `sudo -- reclaim --helper <terminate|freeze|thaw> --grace … pid:starttime …`.
  The helper is a small non-interactive code path. It re-validates every
  `(pid, starttime)`, refuses PID 1, kernel threads and anything protected by
  the **system** defaults, does the same pidfd sequence, and prints a JSON
  result. sudo handles password prompting and caching, and reclaim never stores
  credentials.

### Protected groups (F8)

`~/.config/reclaim/config.toml`:

```toml
grace = "5s"

[protect]
names   = ["firefox"]             # comm / unit-derived name
exes    = ["/usr/bin/keepassxc"]  # resolved exe path
cgroups = ["*/app-*-keepassxc-*.scope"]  # glob on cgroup path
```

Defaults are detected at runtime and always present unless disabled by name:

- reclaim itself and its whole ancestor chain (shell, terminal emulator, tmux
  client)
- the tmux server, found from `$TMUX` (`socket,pid,session`), since it isn't an
  ancestor
- `sshd`, the login session's `session-N.scope` leader, and `systemd --user`
- the compositor and display server: `gnome-shell`, `kwin_wayland`, `sway`,
  `Hyprland`, `mutter`, `Xorg`, `Xwayland`, …
- PID 1 and kernel threads, which can't be overridden at all

**Override:** the dialog asks the user to type the group name. There is no
config flag to skip this.

## Suggestions (F9–F12)

`suggest.For(group, sysState) []Suggestion{Cmd, Why, Effect, Caveat}`. Arguments
are always shell-quoted, and `sudo` is prefixed when the target is rootful or
system-level.

- **Containers:** `podman|docker stop <name>`, `… pause <name>`. The runtime
  comes from the cgroup pattern, which is confirmed with `exec.LookPath`.
  Rootless podman gets no sudo.
- **Pods (kind):** `kubectl --context kind-<cluster> -n <ns> delete pod <name>`.
  When the owner is a Deployment or StatefulSet (from `ownerReferences`), it
  also offers `kubectl … scale deploy/<name> --replicas=0` and notes that
  deleting the pod alone will reschedule it.
- **kind cluster:** `kind delete cluster --name <cluster>`, using the cluster's
  summed estimate.
- **VMs:** `virsh -c <uri> shutdown|managedsave <name>`. Balloon:
  `virsh -c <uri> setmem <name> <KiB> --live`, with a target suggested from the
  guest's current use when `dommemstat` is readable, and a caveat that the guest
  needs a balloon driver.
- **Kernel:**
  - `sync && echo 1 | sudo tee /proc/sys/vm/drop_caches`, labelled "usually
    pointless: the kernel already frees page cache on demand, and you'll pay to
    re-read it"
  - `echo 1 | sudo tee /proc/sys/vm/compact_memory`, labelled "helps only with
    fragmentation (hugepage allocation failures)"
  - `sudo swapoff -a && sudo swapon -a`, offered **only** when
    `MemAvailable > 1.25 × SwapUsed`, otherwise shown disabled with the
    shortfall. zram swap is called out, because flushing it moves compressed
    pages back as uncompressed.
- **Clipboard (F12):** `y` copies via OSC 52
  (`ESC ] 52 ; c ; <base64> BEL`). Inside tmux, the sequence is wrapped in a DCS
  passthrough (`ESC Ptmux; … ESC \`) and the user is told about
  `set -g set-clipboard on` if needed. GNU screen is handled the same way. The
  command is always shown in a selectable box too, because some terminals ignore
  OSC 52.

## UI sketch

```
 reclaim  mem 27.1/31.2G  avail 4.1G  swap 6.2/8G  PSI some 18% ⚠  [view: apps]
┌ Groups ─────────────────────────────── USS ─── PSS ── Swap ── Δ10m ── PSI ┐
│ ▸ code                               3.8G    4.3G   1.1G   +1.2G   21% ⚑ │
│ ▸ kind: dev (3 nodes, 41 pods)       5.2G    5.6G   0.4G   +80M     6%   │
│ ▸ firefox                     🔒     2.9G    3.6G   0.9G   +10M     2%   │
└───────────────────────────────────────────────────────────────────────────┘
┌ System ───────────────────────────────────────────────────────────────────┐
│ anon 14.2G [action]  cache 7.9G [kernel]  slab 1.1G/0.4G [kernel/no] …    │
└───────────────────────────────────────────────────────────────────────────┘
 v view  s sort  enter expand  t terminate  f freeze  F frozen  c commands  y copy  ? help
```

## Milestones

Each one ends with something usable and tested.

| # | Scope | Done when |
|---|---|---|
| M0 | Scaffold: `go.mod`, `cmd/reclaim`, Makefile, CI (vet, staticcheck, test, `-race`), goreleaser stub | CI green on an empty TUI that quits |
| M1 | `procfs`, `cgroupfs`, `sample`, `model`; `reclaim --dump` JSON | Fixture tests for every parser; `--dump` runs on a real host; degraded output for unreadable PIDs |
| M2 | `group` (all three views), `detect`, read-only TUI, sorting, expand/collapse | Golden tests for each view from fixture snapshots; works on a host with podman + kind |
| M3 | `sysmem` panel with tags and explanations | Breakdown sums to `MemTotal` within the "unaccounted" row |
| M4 | `history`, `pressure`, culprit flag, Δ column | Synthetic pressure test (stress-ng/allocator in a cgroup) flags the right group |
| M5 | `suggest`, `clipboard` | Table tests for every command builder, including quoting; OSC 52 verified in tmux and over ssh |
| M6 | `protect`, confirmation dialog, **terminate** | Integration test: spawn a process tree, terminate it, verify the grace/kill sequence; protected default set verified from inside tmux |
| M7 | **freeze/resume**, frozen registry, quit prompt | Integration test against a delegated user cgroup (skipped if not available) and the SIGSTOP fallback |
| M8 | sudo helper path, root-launch warning, polish | Manual test acting on another user's process; helper rejects stale `(pid, starttime)` |
| M9 | Docs (README, man page from `--help`), packaging, v0.1.0 | Release artifacts built by CI |

M0–M5 make up a safe, read-only release, which could be tagged `v0.1.0-alpha`.
Direct actions arrive in M6–M8.

## Testing strategy

- **Parsers:** golden fixtures captured from real hosts (Fedora/GNOME,
  Ubuntu/KDE, Arch/sway, a host with podman + kind + libvirt). They are
  anonymized and checked into `testdata/`.
- **Grouping and estimates:** pure functions over `model.Snapshot`, tested with
  tables.
- **Actions:** real child processes in tests, with a dedicated test cgroup when
  `systemd-run --user --scope` is available.
- **UI:** `teatest` golden output for each view and dialog.
- **Safety invariants as tests:** PID 1 is never signalled, a protected group
  needs an override, a stale `(pid, starttime)` is refused, and the dialog
  defaults to Cancel.

## Risks

| Risk | Mitigation |
|---|---|
| `smaps_rollup` cost on hosts with many large processes | Adaptive refresh, worker pool, cache; measure in M1 and set a budget (< 5% of one core) |
| PID reuse between snapshot and action | pidfds opened at plan time; `(pid, starttime)` across the sudo boundary |
| Rootless/nested cgroup layouts vary across distros and runtimes | Pattern table in `detect` with fixtures per layout; anything unmatched falls back to "Host" instead of misclassifying |
| Culprit heuristic misleads | Always show the evidence behind the flag; weights configurable; never act on it automatically (non-goal) |
| Freeze leaves an app stuck if reclaim crashes | Persistent frozen registry, reconciled at startup |

## Open question: leak and growth detection

**Recommendation: yes, but kept small.** The `history` ring buffers needed for
the culprit score (F4) already hold per-group USS over the session. Exposing
that costs little:

- a **Δ column** (configurable window, default 10 min) and a sparkline in the
  group detail pane
- a "steady growth" annotation when a linear fit over at least 10 min has a
  positive slope with R² > 0.8 and Δ > 256 MB, for example "this LSP grew
  1.2 GB in 20 min"

Out of scope: persisting history across runs, alerts or notifications, and
calling anything a "leak". The tool reports growth, and the user draws the
conclusion. This fits in M4 at little extra cost.

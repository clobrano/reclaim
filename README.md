# reclaim

reclaim is a terminal UI for developers that shows where memory goes, in groups
you recognize: an IDE, a kind cluster, a VM. It estimates honestly how much
each action would free.

It acts directly only on process groups, and only after you confirm. For
containers, VMs and kernel-level reclaim, it gives you the exact command to
run instead.

```
 reclaim  RAM 27G/31G used · 4.1G available  swap 6.2G/8.0G  PSI some 18.0% full 2.0%
 view apps  sort uss  1 frozen (F)
 ▲ pressure culprit: code — grew +900M in 1m0s, 35% of stall time
 Group                                      Flag      USS      PSS   Shared     Swap   Δ10m    PSI
▸ code                       app            CG      3.8G     4.3G     310M     1.1G  +1.2G    21%
▸ kind: dev (3 nodes, 41 pods)  kind-cluster        5.2G     5.6G     220M     400M   +80M     6%
▸ firefox                    app              P     2.9G     3.6G     700M     900M   +10M     2%
 anon 14G[action]  cache 7.9G[kernel]  slab 1.1G[kernel]  slab-u 400M[no]  shmem 1.0G[action]  …
 v view  s sort  ⏎ expand  t terminate  f freeze  F frozen  c commands  K kernel  m memory  i info  ? help  q quit
```

## Install

reclaim needs Linux and Go 1.24 or later to build. It has no third-party
dependencies.

```sh
go install github.com/clobrano/reclaim/cmd/reclaim@latest
# or, from a checkout
make build
```

It works best with cgroup v2, a 5.3 or later kernel (for pidfds) and PSI
enabled (`CONFIG_PSI`; some distributions need `psi=1` on the kernel command
line). When a feature is missing, reclaim says so in the header and turns off
only what depends on it.

## What it shows

- **Three views**, switched with `v`:
  - apps and systemd scopes, from cgroup v2
  - containers, pods (kind clusters shown as cluster → node → pod →
    container) and libvirt VMs
  - the process tree
- **Honest accounting.** USS, PSS, shared and swap come from `smaps_rollup`.
  RSS is shown for reference only. Stopping a group is estimated to free
  between Σ USS + Σ SwapPss and Σ PSS + Σ SwapPss.
- **System breakdown** (`m`). Each category is explained in plain words and
  tagged with one of:
  - *the kernel frees this itself*
  - *freeable by an action*
  - *not reclaimable*
- **Pressure and culprit.** PSI is shown for the system and for each cgroup.
  The group driving pressure is flagged `C`, based on its share of stall time
  and its recent growth, and the evidence is shown with the flag.
- **Growth.** The Δ column shows growth over a window. Steady growth over the
  session is flagged `G`, for example "grew +1.2G in 20m".

## What it does

- **Terminate** (`t`) sends SIGTERM, waits a grace period (`+`/`-` in the
  dialog), then sends SIGKILL. When the group's cgroup supports it, it also
  writes `cgroup.kill` to catch processes forked during the grace period.
- **Freeze** (`f`) uses `cgroup.freeze` when it can write it, and SIGSTOP
  otherwise. Freezing frees no RAM by itself: it lets the kernel swap the pages
  out under pressure. Frozen groups are listed under `F`, where you can resume
  them. The list is saved, so a frozen group is never forgotten.
- **The confirmation dialog** shows the expected memory freed, the PIDs and
  any warnings. Its default button is Cancel.
- **Protected groups** need you to type the group's name to override the
  protection. PID 1 and reclaim itself can never be stopped.
- **Processes are held by pidfd** from the moment the dialog opens, so a reused
  PID never receives the signal.
- **Least privilege.** reclaim runs as you. To act on another user's
  processes, it runs `sudo reclaim --helper …`, which checks every target again
  before acting.

## What it suggests

`c` on a container, pod, kind cluster, VM or systemd service, or `K` for
kernel-level commands, opens a list of commands you can copy with `y`. Copying
uses OSC 52, so it works inside tmux and over ssh. Examples: `podman stop`,
`kubectl scale … --replicas=0`, `kind delete cluster`, `virsh managedsave`,
`virsh setmem`, `drop_caches` (with a note that it's usually pointless), and a
swap flush, which is offered only when there is enough free RAM to absorb it.

reclaim never runs these commands itself.

## Configuration

`~/.config/reclaim/config.toml` (all keys optional):

```toml
interval = "2s"   # refresh
grace    = "5s"   # SIGTERM → SIGKILL

[protect]
names   = ["firefox"]                    # group or process name
exes    = ["/usr/bin/keepassxc"]         # resolved executable path
cgroups = ["*/app-*-keepassxc-*.scope"]  # glob on the cgroup path; * spans /
disable_defaults = []                    # e.g. ["sshd", "tmux", "ancestors"]

[culprit]
window = "60s"
threshold = 10        # system PSI "some avg10" percent before flagging
psi_weight = 0.4
growth_weight = 0.6

[growth]
window = "10m"        # the Δ column
min_span = "10m"      # steady-growth annotation
min_delta_mb = 256
```

These are protected by default:

- reclaim itself and its ancestors (your shell and terminal)
- the tmux server running reclaim
- `sshd`
- your systemd user manager
- the session, the compositor and the display server

## Other modes

```sh
reclaim --dump [--view containers]   # one snapshot as JSON
reclaim --no-resolve                 # don't ask podman/docker/kubectl for names
```

## Development

```sh
make check   # gofmt, go vet, go test -race
```

[PLAN.md](PLAN.md) describes the design and the milestones.

# keepnick — hold a nick while you are offline

A global ZNC module for networks *without* NickServ (IRCnet-style), where the
only way to keep a nick is to keep a connection logged in with it.

For every enabled network the module opens a **synthetic IRC connection**
("clone"): an independent TCP/TLS socket with a minimal IRC session
(`PASS`/`NICK`/`USER`, answers `PING`, nothing else). The clone is not
attached to any ZNC user and holds the nick while the real user is offline.
When the real user connects and wants the nick, the clone hands it over.

## Configuration

Admins only. Talk to `*keepnick` from any network of the user whose nicks
you want to configure:

```
Msg *keepnick
Add <nick> [nick ...]   hold the given nick(s) on this network
Del <nick> [nick ...]   stop holding the given nick(s)
List                    show everything, including which nick each clone holds
On / Off                enable / disable keepnick on this network
Take                    hand the held nick over to this network right now
Interval [seconds]      minimum time between attempts (default 30, 30..3600)
Rotation [on|off]       try nick1..nick9 before moving to the next listed nick
FreeBind [on|off]       bind clones to unassigned vhost addresses (Linux only)
```

Everything is persisted in the module's NV store (`nicks:<user>/<network>`,
`enabled:<user>/<network>`, `interval`, `rotation`, `freebind`).

## Attempt and retry policy

* Candidates are tried in list order; with `Rotation on`, each listed nick is
  also tried with numeric suffixes (`nick1`..`nick9`, within the server's
  NICKLEN, learned from `005 NICKLEN`) before moving on.
* `432/433/436` while registering: advance to the next candidate.
* A connection attempt is started at most every `Interval` seconds.
* Repeated failures back off exponentially (30s → 1h cap). Replies that mean
  "you are not welcome" (`465 ERR_YOUREBANNEDCREEP`, `ERROR ... banned /
  K-lined`) back off much harder (at least 10 minutes) so the clone never
  hammers a server that k-lined it.
* Clones reconnect automatically; the module keeps at most one clone per
  network and a global cap of 32 clones.

## Handoff to the real user

The module releases a nick only via a `NICK` change to a temporary nick
(e.g. `nick-kn`). A nick freed by a `NICK` change can be taken immediately;
a nick freed by `QUIT` is usually delayed by the server (IRCnet nick delay),
which is why the clone never quits to release a nick.

A handoff starts when the real network

* finishes registering while already using the held nick,
* changes its own nick to the held nick, or
* gets `433` during registration because the clone holds the nick — the
  clone releases it immediately so ZNC's retry can succeed.

The clone then sits on the temporary nick for up to 60 seconds. If the user
takes the nick in time, the clone disconnects (and re-establishes itself only
when the user loses the nick again). If not, the clone takes the nick back
and waits for the next opportunity. If a third party snipes the nick during
the handoff, the clone takes it back and retries later with backoff.

While the user is online and using one of the listed nicks, the module stays
idle; a clone is only (re)spawned when the nick is free of the user.

## IP_FREEBIND on the clone sockets

The clone binds its source address to the network's vhost. To allow vhost
addresses that are not assigned to any interface (e.g. one address of a
routed IPv6 /48), the clone sockets set `IP_FREEBIND` (or `IPV6_FREEBIND`
for v6) before `bind()` — Linux only, and only on the module's own clone
sockets. If the vhost is unresolvable or `bind()` fails, the attempt is
backed off and retried like any other failure. `FreeBind off` restores plain
ephemeral binding.

## Implementation notes

* `modules/keepnick.cpp` — the module (global; load with
  `/znc LoadModule keepnick` as admin, or `Global` in the config).
* `modules/keepnick_utils.h` — pure helpers (nick grammar, NICKLEN
  truncation, suffix/temp nicks, backoff arithmetic, candidate rotation),
  unit-tested in `test/KeepNickTest.cpp`.
* The DNS lookup for the server and vhost runs on a worker thread
  (`CModuleJob`); the numeric addresses are then dialed on the main thread.
* The clone socket is created manually (socket → `IP_FREEBIND` → `bind()` →
  non-blocking `connect()`) and then adopted by the socket manager with
  `ConnectFD()`, entering the normal Csocket state machine at
  `CST_CONNECTWAIT`. TLS (if the server uses it) is verified against the
  configured server hostname exactly like ZNC's own connections.

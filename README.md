# vpnet – Cross-Platform Layer-2 VPN in Pure C
A clean, cross‑platform Layer‑2 VPN implemented in pure C — minimal, modular, and designed for real-world use.

Key features
- switchd — virtual Ethernet switch with MAC learning, broadcast and unicast forwarding.
- vportd — virtual port daemon with platform-specific backends (TAP, UTUN, Wintun).
- Modular code layout: core/ (shared logic), os/ (platform abstractions), src/ (daemons & utilities).
- Custom UDP-based VPN transport, optimized for simplicity and portability.
- Targeted platforms: Linux, macOS, Windows.

Status
- Early development: architecture fully planned; foundational components are being implemented.
- Focus: clean abstractions, cross-platform portability, and a small, auditable codebase.

Get involved
- Contributions, feedback, and design ideas are welcome — check the docs and issue tracker for current goals and tasks.
- Ideal for systems programmers and network engineers interested in lightweight virtual L2 networking.
# vpnet – Cross-Platform Layer-2 VPN in Pure C
A clean, cross-platform Layer-2 VPN implemented in pure C — minimal, modular, and designed for real-world use.

## Key features
- **switchd** — virtual Ethernet switch with MAC learning, broadcast and unicast forwarding  
- **vportd** — virtual port daemon with platform-specific backends (TAP, UTUN, Wintun)  
- **Modular architecture:**  
  - `core/` — shared protocol + switching logic  
  - `os/` — platform abstraction layers  
  - `src/` — daemons (switchd, vportd)  
- **Custom UDP-based VPN transport**, optimized for simplicity and portability  
- **Targeted platforms:** Linux, macOS, Windows

## Status
- **Early development**  
- Architecture fully planned  
- Foundational components implemented  
- Focus on:  
  - clean abstractions  
  - cross-platform portability  
  - small, auditable codebase

## Get involved
- Contributions, feedback, and design ideas are welcome  
- Check issues for current goals & tasks  
- Ideal for:
  - systems programmers  
  - networking people  
  - anyone wanting lightweight virtual L2 networking
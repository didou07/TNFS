# TNFS — TVCAS Newcamd Fake Stream

A GUI tool for testing Newcamd TVCAS servers by sending synthetic ECM streams and measuring CW responses.

Supports **TVCAS3** and **TVCAS4** master keys, runs on **Linux (GTK3)** and **Windows (Win32)**.

---

## Features

- Newcamd protocol client (login, CARD_DATA_REQ, ECM send/recv)
- Built-in DES / 3DES-EDE2-CBC / MD5-crypt — no OpenSSL dependency
- TVCAS4 → TVCAS3 master key conversion
- ECM builder with even/odd CW rotation
- Timestamped log with hit/nok/err stats
- Config auto-saved to `tnfs.conf`

---

## Build

### Linux (GTK3)

```bash
sudo apt install libgtk-3-dev   # Debian/Ubuntu
# or
sudo dnf install gtk3-devel     # Fedora

make
./tnfs
```

### Windows (MinGW cross-compile from Linux)

```bash
sudo apt install mingw-w64
make CC=x86_64-w64-mingw32-gcc OS=Windows_NT
```

### Windows (native MinGW/MSYS2)

```bash
make
```

---

## Configuration

Fields are saved automatically to `tnfs.conf` on stop/close.

| Field      | Description                          | Default                        |
|------------|--------------------------------------|--------------------------------|
| HOST       | Newcamd server address               | `127.0.0.1`                    |
| PORT       | Newcamd server port                  | `15050`                        |
| USER       | Username                             | `tvcas`                        |
| PASS       | Password                             | `1234`                         |
| DES KEY    | 14-byte DES key (28 hex chars)       | `010203...14`                  |
| CAID       | CA ID (hex)                          | `0B00`                         |
| SID        | Service ID (hex)                     | `0001`                         |
| PROVID     | Provider ID (hex)                    | `000000`                       |
| MASTER KEY | 32-byte ECM encryption key (64 hex)  | (built-in test key)            |
| INTERVAL   | Seconds between ECM sends            | `10`                           |
| TVCAS4     | Check if master key is TVCAS4 format | unchecked                      |

---

## Log output

```
2025/01/15 12:34:56 (newcamd) 127.0.0.1 connecting ....
2025/01/15 12:34:56 [card] CAID from server: 0B00
2025/01/15 12:34:57 (cw) [hit]  0B00:0001:80  [37]  A1B2C3D4E5F60708 0000000000000000  142ms  tvcas
2025/01/15 12:35:07 (cw) [hit]  0B00:0001:81  [37]  ...
2025/01/15 12:35:17 --- Stop ---
2025/01/15 12:35:17   Total: 2 OK  |  0 NOK  |  (2 sent)
2025/01/15 12:35:17 server is decrypting ECM correctly
```

---

## Project structure

```
tnfs/
├── Makefile
├── include/
│   ├── platform.h     platform abstraction (Win32 / POSIX)
│   ├── crypto.h       DES, 3DES-EDE2, MD5
│   ├── util.h         sockets, hex, time helpers
│   ├── tvcas.h        TVCAS4 -> TVCAS3 key transform
│   ├── newcamd.h      Newcamd protocol client
│   ├── ecm.h          ECM payload builder
│   ├── config.h       tnfs.conf load/save
│   ├── log.h          thread-safe UI log
│   └── worker.h       background ECM thread
└── src/
    ├── crypto.c
    ├── util.c
    ├── tvcas.c
    ├── config.c
    ├── ecm.c
    ├── newcamd.c
    ├── worker.c
    ├── log.c
    └── main.c         Win32 / GTK3 UI
```

---

## License

MIT

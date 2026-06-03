# TNFS — TVCAS Newcamd Fake Stream

A GUI testing tool for TVCAS Newcamd servers.  
Sends fake ECM streams and verifies that the server returns valid Control Words (CW).

## Features

- Newcamd protocol client
- Fake ECM stream generator with configurable interval
- TVCAS3 / TVCAS4 master key support with automatic conversion
- DES / 2DES-EDE-CBC session key handling
- Cross-platform: Linux (GTK 3) and Windows (Win32 API)

## Build

**Linux:**
```bash
sudo apt-get install libgtk-3-dev pkg-config
make linux
```

**Windows (cross-compile from Linux):**
```bash
sudo apt-get install mingw-w64
make windows
```

## Usage

1. Fill in the server connection fields (Host, Port, User, Pass)
2. Set the DES key, CAID, SID, ProvID, and Master Key
3. Select **TVCAS4** checkbox if the master key is in TVCAS4 format — it will be converted to TVCAS3 automatically
4. Click **Run Test** — results appear in the log
5. Click **Stop** to end the session

## Releases

Pre-built binaries for Linux and Windows are available on the [Releases](../../releases) page.

## License

MIT

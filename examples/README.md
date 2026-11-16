# Example lab snapshot

`lab-server/` is a **synthetic, deliberately imperfect** Linux server snapshot
used by the test suite and by the README demo:

```bash
baseaudit audit --root examples/lab-server
```

It is not a real host and contains no credentials: the password hashes are
obvious placeholders.

Two conventions are worth knowing when reading the tree:

* `/etc/systemd/system/*.wants/` entries are stored as **plain files whose
  content is the symlink target**. Git checkouts on Windows default to
  `core.symlinks=false`, and the auditor only uses the unit *name* from the
  directory listing, so a represented symlink works exactly like a real one.
* `var/lib/apt/periodic/update-success-stamp` is an empty marker file. Its
  modification time drives the "package metadata freshness" rule, so the
  result depends on when the repository was checked out.

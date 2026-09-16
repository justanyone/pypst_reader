# pstreader — an alias for [pypstreader](https://github.com/justanyone/pypstreader)

This distribution contains no implementation. It installs
**[`pypstreader`](https://pypi.org/project/pypstreader/)**, the pure-Python
reader for Outlook PST stores, and re-exports it under the shorter name.

```bash
pip install pstreader
```

```python
import pstreader                      # the same objects as `import pypstreader`

with pstreader.open("store.pst") as store:
    for folder in store.root_folder.walk():
        print(folder.display_name, folder.content_count)
```

```bash
pstreader store.pst        # identical to `pypstreader store.pst`
```

`pstreader.__version__` is `pypstreader.__version__`, and the dependency is
pinned exactly (`pypstreader==0.1.0`), so the two names can never mean two
different readers in one environment.

**Use `pypstreader` in anything you publish.** That is where the code, the
issues, the documentation and the release notes live; this name is here so
that typing the obvious thing works.

MIT, like the package it aliases. See
[the project README](https://github.com/justanyone/pypstreader#readme) for
what the reader actually does.

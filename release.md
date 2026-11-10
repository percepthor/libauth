# Create a libauth Release

1. Update the version in `include/auth/version.h` (with its date and time) and in `version.txt`, the changes of the
release in `CHANGELOG.md`, and its breaking changes in `incompatibilities.md`

2. Run the gate against the cerver of the release, from clean sources

```
CERVER_DIR=/path/to/cerver bash test/gate.sh
```

3. Merge into `main`: `.github/workflows/release.yml` creates the release with the version of `version.txt` and the
changes of `CHANGELOG.md`

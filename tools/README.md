# Optional tools

The app works in evidence-only mode without external Android tools. For richer metadata and source rebuild/export verification, add these tools to PATH:

- `aapt2` (Android SDK build-tools): package name and version metadata
- `apktool`: rebuild a user-owned source/backup project
- `apksigner`: signature verification after export
- `jadx`: optional manual decompilation workflow; the app never decompiles or modifies third-party code automatically

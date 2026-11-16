# Veylora Release Signing

The release workflow can sign and publish Veylora v1.0.0 after repository signing secrets are configured.

## 1. Create a private release keystore

Run this on your own trusted computer with a JDK installed:

```bash
keytool -genkeypair -v -keystore veylora-release.jks -keyalg RSA -keysize 4096 -validity 10000 -alias veylora
```

Choose strong, unique passwords when prompted. Keep the keystore file and passwords private. Make at least one secure backup. **Never commit the keystore to this repository or send it in chat.** Losing the keystore can prevent signing future updates with the same app identity.

## 2. Encode the keystore

Linux/macOS:

```bash
base64 -w 0 veylora-release.jks
```

On macOS, if `-w` is unsupported:

```bash
base64 < veylora-release.jks | tr -d '\n'
```

Windows PowerShell:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("veylora-release.jks"))
```

Copy the resulting Base64 text locally. Do not paste it into chat or a source file.

## 3. Add four GitHub Actions repository secrets

Open the repository's **Settings → Secrets and variables → Actions → New repository secret** and add:

| Secret name | Value |
|---|---|
| `KEYSTORE_BASE64` | The Base64-encoded keystore content |
| `KEYSTORE_PASSWORD` | The keystore password |
| `KEY_ALIAS` | `veylora` (or the alias you chose) |
| `KEY_PASSWORD` | The key password |

Do not put these values in GitHub files, commits, issues, or chat messages.

## 4. Build and publish the signed release

After saving all four secrets, open **Actions → Android Build → Run workflow** and run it on `main`.

The workflow will:
- run tests, lint, and APK builds;
- sign the release APK with the private keystore;
- verify the APK signature;
- upload the signed APK artifact;
- create or update the GitHub release tagged `v1.0.0`.

If the secrets are not configured, the normal CI build still succeeds, but signing and publishing are skipped.

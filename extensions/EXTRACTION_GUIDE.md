# Guide: Extracting Chrome Extensions NOT on the Web Store

This guide documents successful methods for obtaining Chrome extensions that are not publicly available on the Chrome Web Store (enterprise, school, or private extensions).

---

## Method 1: Find the Update URL from an Existing Manifest

**When to use:** You have an already-extracted extension or access to its manifest.json

**How it works:**
1. Open the extension's `manifest.json`
2. Look for the `update_url` field
3. Fetch the update URL to get the XML manifest
4. Download the CRX from the `codebase` URL in the XML

**Example - GoGuardian:**
```bash
# From manifest.json:
# "update_url": "https://ext.goguardian.com/stable.xml"

# Fetch the update manifest:
curl -s "https://ext.goguardian.com/stable.xml"
# Returns:
# <updatecheck codebase='https://crx.goguardian.com/extension-m-4.0.7393.1-stable-crx2.crx' version='4.0.7393.1' />

# Download the CRX:
curl -L -o goguardian.crx "https://crx.goguardian.com/extension-m-4.0.7393.1-stable-crx2.crx"
```

**Extensions extracted this way:**
- GoGuardian (`haldlgldplgnggkjaafhelgiaglafanh`) - update_url in manifest
- GoGuardian License (`bfijnabjihmoknklklebejaljjfdnlmo`) - update_url in manifest

---

## Method 2: Search Deployment Documentation

**When to use:** You know the extension name and vendor but don't have the files

**How it works:**
1. Search for: `"[extension name]" chrome extension deployment intune OR "update_url"`
2. Look for enterprise deployment guides (Microsoft Intune, Google Admin Console, etc.)
3. These guides often contain the extension ID and update URL

**Example - StudentKeeper:**
```bash
# Search found Ativion's Intune deployment guide which contained:
# johiffgefcnfiddcakohlcpebgpidnji;https://cdn.imp.contentkeeper.net/clients/production/chrome/update-manifest.xml

# Fetch the update manifest:
curl -s "https://cdn.imp.contentkeeper.net/clients/production/chrome/update-manifest.xml"
# Returns:
# <updatecheck codebase='https://cdn.imp.contentkeeper.net/clients/production/chrome/ChromeUniversalClient.crx' version='1.2.19.1232' />

# Download:
curl -L -o studentkeeper.crx "https://cdn.imp.contentkeeper.net/clients/production/chrome/ChromeUniversalClient.crx"
```

**Extensions extracted this way:**
- StudentKeeper (`johiffgefcnfiddcakohlcpebgpidnji`) - found in Intune deployment docs

---

## Method 3: Query the Update URL Directly

**When to use:** You have an extension ID and want to check common vendor update endpoints

**Common update URL patterns:**
```bash
# Generic format - query with extension ID:
https://[vendor-domain]/update?x=id%3D[EXTENSION_ID]%26v%3D0

# GoGuardian:
https://ext.goguardian.com/stable.xml
https://ticketmaster.goguardian.com/update

# ContentKeeper/Ativion:
https://cdn.imp.contentkeeper.net/clients/production/chrome/update-manifest.xml

# Securly:
https://extension.securly.com/updates.xml

# Generic Google format (only works for Web Store extensions):
https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0.0.0&acceptformat=crx2,crx3&x=id%3D[EXTENSION_ID]%26uc
```

---

## Method 4: Calculate Extension ID from Public Key

**When to use:** You have a CRX/manifest but need to verify the extension ID

**How it works:**
The extension ID is derived from the SHA256 hash of the public key, converted to a-p alphabet.

```python
import hashlib
import base64

def get_extension_id(public_key_b64):
    key_bytes = base64.b64decode(public_key_b64)
    hash_bytes = hashlib.sha256(key_bytes).digest()[:16]
    return ''.join(chr(ord('a') + (b >> 4)) + chr(ord('a') + (b & 0xf)) for b in hash_bytes)

# Example:
key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPdMH1s..."
print(get_extension_id(key))  # haldlgldplgnggkjaafhelgiaglafanh
```

**Bash one-liner:**
```bash
echo "BASE64_KEY_HERE" | base64 -d | sha256sum | head -c 32 | tr '0-9a-f' 'a-p'
```

---

## Method 5: Extract CRX to Unpacked Extension

**When to use:** You have a .crx file and need the source files

**How it works:**
CRX files are ZIP archives with a header. Find the ZIP signature and extract.

```bash
# Method A: Direct unzip (sometimes works)
unzip extension.crx -d unpacked/

# Method B: Skip CRX header (more reliable)
python3 -c "
with open('extension.crx', 'rb') as f:
    data = f.read()
    idx = data.find(b'PK')  # ZIP signature
    with open('extension.zip', 'wb') as out:
        out.write(data[idx:])
"
unzip extension.zip -d unpacked/
```

---

## Method 6: Chrome Enterprise Policy Installation

**When to use:** You want to install an extension as "Managed by your organization"

**How it works:**
Create a policy file that force-installs the extension.

**Linux:**
```bash
# Create policy directory
sudo mkdir -p /etc/opt/chrome/policies/managed

# Create policy file
sudo tee /etc/opt/chrome/policies/managed/extensions.json << 'EOF'
{
  "ExtensionInstallForcelist": [
    "EXTENSION_ID;UPDATE_URL"
  ]
}
EOF

# Example for GoGuardian + StudentKeeper:
{
  "ExtensionInstallForcelist": [
    "haldlgldplgnggkjaafhelgiaglafanh;https://ext.goguardian.com/stable.xml",
    "bfijnabjihmoknklklebejaljjfdnlmo;https://ticketmaster.goguardian.com/update",
    "johiffgefcnfiddcakohlcpebgpidnji;https://cdn.imp.contentkeeper.net/clients/production/chrome/update-manifest.xml"
  ]
}

# Restart Chrome - extensions will auto-download and show as "Managed"
```

---

## Summary of Extracted Extensions

| Extension | ID | Update URL | Method |
|-----------|----|-----------:|--------|
| GoGuardian | `haldlgldplgnggkjaafhelgiaglafanh` | `https://ext.goguardian.com/stable.xml` | Manifest |
| GoGuardian License | `bfijnabjihmoknklklebejaljjfdnlmo` | `https://ticketmaster.goguardian.com/update` | Manifest |
| StudentKeeper | `johiffgefcnfiddcakohlcpebgpidnji` | `https://cdn.imp.contentkeeper.net/clients/production/chrome/update-manifest.xml` | Deployment Docs |
| CKAuthenticator | `jdogphakondfdmcanpapfahkdomaicfa` | Chrome Web Store | Web Store |

---

## Files in This Directory

```
extracted_extensions/
├── goguardian.crx              # GoGuardian main extension
├── goguardian-unpacked/        # Extracted source
├── goguardian-license.crx      # GoGuardian License
├── goguardian-license-unpacked/
├── studentkeeper.crx           # StudentKeeper/Ativion
├── studentkeeper-unpacked/     # Extracted source
├── ckauthenticator.crx         # ContentKeeper Authenticator
└── EXTRACTION_GUIDE.md         # This file
```

---

## Notes

- **Enterprise extensions** often don't have a `key` in their manifest - the ID is assigned during policy deployment
- **Update URLs** return XML manifests in Google's update protocol format
- **CRX versions**: v2 (older) and v3 (newer) - both can be extracted the same way
- **Chrome policies** take precedence over manual installation and show as "Managed by your organization"

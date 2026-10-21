# Changes in this fork: built-in eMudhra compromised intermediate CAs

This fork replaces ProxyPin's **built-in signing CA with the 8 compromised eMudhra intermediate CAs** (you can pick
any one of the 8), so HTTPS man-in-the-middle (MITM) capture works **out of the box on a device that is not rooted and
has not yet patched this issue** — no need to install the CA into the system trust store, and no Magisk/Xposed.

**How to choose** — via the new “Signing CA” entry:
- Desktop: HTTPS menu → Signing CA → Signing CA / Trust path
- Mobile: HTTPS settings → Signing CA

The options are the 8 eMudhra intermediates (DV/OV/EV/CS × G3B/G3C) plus the built-in ProxyPin root, and two trust
paths (emSign / Sectigo AAA). In the list, TLS entries show ✓ (chain to a widely trusted anchor); CS entries and the
local root show ⚠ (limited / requires manual install).

**Why no root is needed**: the private keys of these 8 intermediates are public (secp384r1, scalar `d` is a single byte).
ProxyPin forges each host's leaf certificate with them, and the leaf chains via
`intermediate → emSign Root TLS/CS CA - G3 → emSign ECC Root CA - G3` (or Sectigo `AAA Certificate Services`)
to a trust anchor that is **already shipped in the device's system store**, so system-level trust is enough to validate.

**Limitation**: only works on “unpatched” devices that still trust these 8 intermediates; systems/browsers that already
distrust them (Mozilla/Apple/Chrome/Microsoft, 2026‑10‑17~20) will show a certificate error. The emSign path for the
CS entries (07/08) only chains to a Microsoft-trusted root.

References: CVE-2026-111943 · disclosure https://emudhra.we-have-a-problem.com/ · reproducible material in the `emudhra-certs/` directory.

Original text below

---

# ProxyPin

English | [中文](README_CN.md)
## Open source free traffic capture HTTP(S)，Support Windows、Mac、Android、IOS、Linux Full platform system

You can use it to intercept, inspect & rewrite HTTP(S) traffic, Support capturing Flutter app traffic, ProxyPin is based on Flutter develop, and the UI is beautiful
and easy to use.

## Features
* Mobile scan code connection: no need to manually configure WiFi proxy, including configuration synchronization. All terminals can scan codes to connect and forward traffic to each other.
* Domain name filtering: Only intercept the traffic you need, and do not intercept other traffic to avoid interference with other applications.
* Search: Search requests according to keywords, response types and other conditions
* Script: Support writing JavaScript scripts to process requests or responses.
* Request Rewrite: Support redirection, support replacement of request or response message, and can also modify request or response according to the increase.
* Request Mapping: Do not request remote services, use local configuration or scripts for response
* Request Decryption: Configure AES decryption key to automatically decrypt HTTP message body
* Request Blocking: Support blocking requests according to URL, and do not send requests to the server.
* History: Automatically save the captured traffic data for easy backtracking and viewing. Support HAR format export and import.
* Others: Favorites, toolbox, common encoding tools, as well as QR codes, regular expressions, etc.

**Mac will prompt untrusted developers when first opened, you need to go to System Preferences-Security & Privacy-Allow any source.**

## Sponsors

If ProxyPin is helpful to you, you are welcome to support us in the following ways to help the project develop in the long term:

* [Buy Me A Coffee](https://buymeacoffee.com/proxypin)
* [AFDIAN](https://afdian.com/a/proxypin)
* Submit feedback and suggestions to help us improve
* Contribute code or documentation to the project

**Your support will be used for project maintenance, feature development, and user experience optimization. Thank you very much!**

## Downloads

Github Releases: https://github.com/wanghongenpin/proxypin/releases

iOS App Store：https://apps.apple.com/app/proxypin/id6450932949

Android Google Play：https://play.google.com/store/apps/details?id=com.network.proxy

TG: https://t.me/proxypin_en

**We will continue to improve the features and experience, as well as optimize the UI.**

<img alt="image"  width="580px" height="420px"  src="https://github.com/user-attachments/assets/6c1345ab-c95c-415d-ac59-470c764b59a2">.<img alt="image"  height="500px" src="https://github.com/user-attachments/assets/3c5572b0-a9e5-497c-8b42-f935e836c164">


### Powered by
[![JetBrains logo.](https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg)](https://jb.gg/OpenSource)
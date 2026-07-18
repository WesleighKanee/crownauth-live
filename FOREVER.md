# CrownAuth — FOREVER policy (locked)

This is the production contract. Do not undo it.

## Always true on every boot / settings save

- Forced OTA **OFF** (ota_enabled=false, orce_update=false)
- min_client_version_code = 0
- min_client_protocol = 0
- Auth rate limit **OFF** (no "Temporarily blocked")
- Server client_update_gate always returns **None** (no ction:update)

## How you operate day to day

1. Open panel: https://crownauth-live.onrender.com
2. Create / ban / delete keys
3. Buyers use the loader they already have
4. Optional new APK: bake + upload GitHub release — **never** force-update buyers

## Never do

- Raise min_vc / min_proto to force Chrome OTA
- Turn on orce_update or ota_enabled
- Turn on rate limiting that bans IPs
- Run old publish_ota.ps1 -PushOld thinking it is safe

## If something breaks

1. Check https://crownauth-live.onrender.com/v2/health →  should be orever_v1
2. Owner login → settings still show min_vc=0, force_update=false
3. Manual Render deploy if code is old
4. Keys still mint/ban in real time even if free tier is slow to wake

## Loader

- Package: com.oken.snahc
- Public name: WhiteCrownsLoaderV2.apk
- Latest safe bake has OTA chrome path no-op

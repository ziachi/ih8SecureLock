# ih8SecureLock (Enhanced Fork)

Prevent apps from blocking and listening to your screenshots with Zygisk. **Enhanced to also bypass FLAG_SECURE on initial window creation** — fixes black screen on scrcpy/virtual displays.

> Forked from [j-hc/ih8SecureLock](https://github.com/j-hc/ih8SecureLock) — all credit to the original author.

## What's changed in this fork

- **Hook `addToDisplayAsUser` / `addToDisplay`** — strips `FLAG_SECURE` at initial window creation, not just on relayout. This fixes scrcpy and other virtual display capture tools that showed black screens because the secure flag was already set before the first relayout.
- **Better logging** — shows SDK level and which hooks are active on load.
- Works with KernelSU or Magisk
- Works on Android versions 10 - 16

## Installation

- Do not put the apps for which you want to take an ss in any kind of denylist and disable "Unmount modules" option for them.

## Verify

```bash
su -c logcat -d -s ih8SecureLock
```

You should see:
```
ih8SecureLock: [xx] [app.package] Hook relayout: code=X
ih8SecureLock: [xx] [app.package] Hook addToDisplayAsUser: code=X
ih8SecureLock: [xx] [app.package] Loaded
ih8SecureLock: [xx] [app.package] Bypassed secure lock (relayout)
ih8SecureLock: [xx] [app.package] Bypassed secure lock (addToDisplay)
```

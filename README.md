#  Vanguard TPM Popup Bypass Tool

This tool was developed for **educational and research purposes only**. It aims to bypass the **TPM/Secure Boot popup** that appears when trying to run Valorant without certain security features enabled.

---

## ⚙ Features

-  Stops and disables the Vanguard service (`vgc`)
- Provides an injection window after Vanguard is down
-  Detects and suspends `vgm.exe` (Valorant’s watchdog)
-  Detects and suspends `svchost.exe` processes that load `tpmcore.dll` (source of the TPM popup)
-  Uses `pssuspend.exe` for safe process suspension (Sysinternals)

---

##  How It Works

1. Waits for the game to launch (`VALORANT-Win64-Shipping.exe`)
2. Checks for admin and debug privileges
3. Stops and configures `vgc` to manual
4. Prompts the user to inject any custom code/cheat
5. Searches for `svchost.exe` with `tpmcore.dll` and suspends it using **Sysinternals' `pssuspend.exe`**
6. Monitors and suspends `vgm.exe` on loop

---

##  Requirements

- Windows 10 or 11 (with admin rights)
- [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend) (`pssuspend.exe`)
- Visual Studio (to compile)
- TPM/Secure Boot turned **off**
- Trusted Platform Module (TPM) **uninstalled** from Device Manager (optional, improves consistency)
- brain!

---

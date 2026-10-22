# CIP-B103 Lab 1 – Disk Forensics: The Hacking Case (SCHARDT.dd)

**Student:** Fuseini Imoru Kantuogaa  
**Course:** CIP-B103  
**Lab:** Lab 1 – Disk Image Forensics & User Attribution Analysis

## Overview

This lab demonstrates a disk forensics workflow on the NIST CFReDS "Hacking Case" image: downloading and reassembling a split disk image, verifying it with MD5 hashes, locating the NTFS partition, extracting registry hives and event logs from the image, identifying the operating system, owner, computer name and time zone, parsing user accounts, mounting the image read-only, and searching for evidence of hacking tools, e-mail/newsgroup/IRC activity, captured network traffic and deleted files. The goal was to determine who used the suspect computer and whether Greg Schardt (alias "Mr. Evil") is a hacker.

## Case Folder Structure

```
cd ~/hacking_case      # SCHARDT.001-.008, SCHARDT.dd, extracted hives, logs and output files
/mnt/loop              # SCHARDT.dd NTFS partition mounted read-only
```

## 1. Tool Setup

The working directory was created and the following tools were used (most are preinstalled in Kali):

```
mkdir hacking_case
cd hacking_case
```

| Tool | Source / Version | Purpose |
|---|---|---|
| The Sleuth Kit (mmls, fls, icat) | Kali package | Partition layout, file listing and file extraction from the raw image |
| RegRipper (rip.pl) | /usr/lib/regripper | Parsing the SOFTWARE, SYSTEM and SAM hives |
| evtparse.pl | git clone https://github.com/keydet89/Tools.git | Parsing the Windows XP SysEvent.Evt log |
| losetup / mount | Linux | Read-only mounting of the image |
| tshark (Wireshark 4.6.6) | Kali package | Reading the pcap file found in the user profile |
| rifiuti2 | apt-get install rifiuti2 | Parsing the Recycle Bin INFO2 file |
| ClamAV (clamscan 1.4.5) | apt-get install clamav | Malware scan of the mounted image |
| strings / grep / egrep / comm | Linux | String carving and keyword searching |

## 2. Acquiring the Disk Image

The image is distributed by NIST in eight segments. The first segment was downloaded with `wget` (a quiet run from www.cfreds.nist.gov, then a visible run from cfreds-archive.nist.gov on 2026-08-26 at 11:04:25; the first segment is 666,238,976 bytes, 635 MB). The segments were joined and each file was hashed:

```
wget https://cfreds-archive.nist.gov/images/hacking-dd/SCHARDT.001
cat SCHARDT.00* > SCHARDT.dd
md5sum SCHARDT*
```

| File | MD5 |
|---|---|
| SCHARDT.001 | 28a9b613d6eefe8a0515ef0a675bdebd |
| SCHARDT.002 | c7227e7eea82d218663257397679a7c4 |
| SCHARDT.003 | ebba35acd7b8aa85a5a7c13f3dd733d2 |
| SCHARDT.004 | 669b6636dcb4783fd5509c4710856c59 |
| SCHARDT.005 | c46e5760e3821522ee81e675422025bb |
| SCHARDT.006 | 99511901da2dea772005b5d0d764e750 |
| SCHARDT.007 | 99511901da2dea772005b5d0d764e750 |
| SCHARDT.008 | 8194a79a5356df79883ae2dc7415929f |
| **SCHARDT.dd** | **aee4fcd9301c03b3b054623ca261959a** |

Segments .006 and .007 have the same hash, which suggests they contain identical data (likely blank/zero-filled space). The combined image hash should be compared with the value published on the NIST CFReDS page to confirm integrity.

## 3. Image Identification (Partition Layout)

```
mmls SCHARDT.dd
fls -rF -o 63 SCHARDT.dd | grep -i software
```

| Field | Value |
|---|---|
| Partition table | DOS Partition Table, 512-byte sectors |
| Partition 002 | NTFS / exFAT (0x07), start sector 63, end 9510479, length 9,510,417 sectors (about 4.9 GB) |
| Unallocated | Sectors 0–62 and 9510480–9514259 |
| Offset used for all Sleuth Kit commands | `-o 63` |

The `fls` search located the registry files under `WINDOWS/system32/config/` (software = inode 336, SysEvent.Evt = inode 3678, SAM = inode 3667), and a Program Files folder containing an Anonymizer toolbar.

## 4. Registry Analysis

The SOFTWARE hive was extracted with `icat -o 63 SCHARDT.dd 336 > software` (8,650,752 bytes) and parsed with RegRipper:

```
perl /usr/lib/regripper/rip.pl -l | grep -i winver
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/software -p winver
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/system -p timezone
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/system -p compname
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/system -p shutdown
```

| Key / Plugin | Finding |
|---|---|
| winver | Microsoft Windows XP, BuildLab 2600.xpclient.010817-1148 |
| RegisteredOwner | **Greg Schardt** (RegisteredOrganization N/A) |
| InstallDate | 2004-08-19 22:48:27 UTC |
| timezone | Central Standard Time / Central Daylight Time, Bias 360 (6 h), ActiveTimeBias 300 (5 h, daylight time in effect); key last written 2004-08-19 17:20:02 UTC |
| compname | ComputerName N-1A9ODN6ZXK4LQ (TCP/IP hostname n-1a9odn6zxk4lq) |
| shutdown | ShutdownTime 2004-08-27 15:46:33 UTC |

The first attempt to parse `~/hacking_case/SOFTWARE` failed because the extracted file was named in lowercase (`software`); it worked after using the correct name.

## 5. System Event Log

The event log was extracted (`icat -o 63 SCHARDT.dd 3678 > SysEvent.Evt`, 64 KB) and converted to a TLN timeline with evtparse:

```
git clone https://github.com/keydet89/Tools.git
perl Tools/source/evtparse.pl -e SysEvent.Evt -t > SysEvent.txt
cat SysEvent.txt
```

| Event | Meaning |
|---|---|
| Workstation/3260 – workgroup EVIL | The computer was a member of a workgroup named EVIL |
| EventLog/6011 | Computer name set to N-1A9ODN6ZXK4LQ |
| Dhcp/1007 (Warn) | No DHCP lease; address 169.254.242.213 (link-local) for adapter MAC 0010A4933E09 |
| W32Time/17 (Error) | Could not reach time.windows.com (unreachable host) |
| Service Control Manager 7035/7036 | Telephony, Network Connections, SSDP Discovery, Network Location Awareness and Remote Access Connection Manager services started |

The network adapter MAC 0010A4933E09 matches the `%LANNIC%` value found later in the Look@LAN configuration (section 7).

## 6. User Account Analysis (SAM)

```
icat -o 63 SCHARDT.dd 3667 > SAM
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/SAM -p samparse
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/SAM -p samparse_tln
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/software -p profilelist
date -d @1093619303
```

| Account (RID) | Created (UTC) | Last login | Login count | Notes |
|---|---|---|---|---|
| Administrator (500) | 2004-08-19 16:59:24 | Never | 0 | Default admin; password reset 17:17:29 |
| Guest (501) | 2004-08-19 16:59:24 | Never | 0 | Password not required |
| HelpAssistant (1000) | 2004-08-19 22:28:24 | Never | 0 | Remote Assistance account |
| SUPPORT_388945a0 (1002) | 2004-08-19 22:35:19 | Never | 0 | Microsoft vendor account, **disabled** |
| **Mr. Evil (1003)** | 2004-08-19 23:03:54 | **2004-08-27 15:08:23** | **15** | Member of Administrators; password does not expire |

Only one human-created account exists, Mr. Evil, and it is the only account that was ever logged into (15 times). The ProfileList key shows a `Documents and Settings\Mr. Evil` profile last written 2004-08-27 15:46:23 UTC, ten seconds before shutdown. The TLN output converts the last login (epoch 1093619303) to Fri Aug 27 15:08:23 UTC (11:08:23 EDT on the Kali host).

## 7. Mounting the Image and Keyword Search

The partition was attached read-only and mounted, then searched for the registered owner name:

```
sudo mkdir /mnt/loop
sudo losetup --partscan --find --show --read-only SCHARDT.dd
sudo mount /dev/loop0p1 /mnt/loop
grep -rn '/mnt/loop/' -e 'Greg Schardt'
grep -in 'evil' "/mnt/loop/Program Files/Look@LAN/irunin.ini"
```

The loop device was `/dev/loop0` with partition `/dev/loop0p1`; the mount reported it could not mount read-write and fell back to read-only, which preserves the evidence. The root of the volume showed a normal Windows XP layout (WINDOWS, Documents and Settings, Program Files, RECYCLER, System Volume Information, plus legacy files such as WIN98).

| Artifact | Finding |
|---|---|
| irunin.ini (Look@LAN) | `%REGOWNER%=Greg Schardt`, `%USERNAME%=Greg Schardt`, `%LANUSER%=Mr. Evil` |
| Look@LAN Setup Log.txt | Value data = Greg Schardt; shortcuts Look@LAN.lnk and Look@Host.lnk created on the Mr. Evil desktop |
| irunin.ini paths | Installer source `C:\Documents and Settings\Mr. Evil\Desktop\lalsetup250.exe` |
| `%LANIP%` | 192.168.1.111 |
| `%LANNIC%` | 0010a4933e09 |

This ties the name Greg Schardt to the Mr. Evil user account and the same network card seen in the event log. A first `cat ... | grep -I 'evil'` returned nothing because `-I` skips files grep treats as binary; `grep -in` found the lines.

## 8. Browser Artifacts

Internet Explorer history was read from the Mr. Evil profile:

```
strings '/mnt/loop/Documents and Settings/Mr. Evil/Local Settings/History/History.IE5/index.dat' | grep -i 'greg'
```

Both `History.IE5/index.dat` and the weekly `MSHist012004081620040823/index.dat` contain a visit by Mr. Evil to `edit.yahoo.com/config/id_check?` with parameters `fn=Greg`, `ln=Schardt` and `id=mrevil2000`, which is a Yahoo account registration. Temporary Internet Files also contain Yahoo! Mail pages signed in as **mrevilrulez@yahoo.com**, including a "Welcome to Yahoo! Mail" message addressed to that account.

An e-mail regular expression run over the profile (`grep -Eiorh ... | sort | uniq -c | sort -nr`) found mrevilrulez@yahoo.com 12 times, followed by info@mosnews.com (6), jim@mcmahon.cc (4), webmaster@2600.com, hacked@2600.com and several Hotmail addresses (PASSCODE, PASSADMINBOT, HERE) that appear in newsgroup content.

## 9. Network Configuration and Installed Software

```
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/software -p networkcards
perl /usr/lib/regripper/rip.pl -r ~/hacking_case/software -p uninstall
egrep -rIl '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' '/mnt/loop/' > ip.txt
egrep -rIl '[^-/]\b[0-9a-fA-F]{12}\b' '/mnt/loop' > mac.txt
comm -12 ip.txt mac.txt
```

| Network card | Key last written (UTC) |
|---|---|
| Xircom CardBus Ethernet 100 + Modem 56 | 2004-08-19 17:07:19 |
| Compaq WL110 Wireless LAN PC Card | 2004-08-27 15:31:44 |

Files containing both an IP and a MAC address were Look@LAN's irunin.ini and mIRC's channels.txt. The Uninstall key lists the software installed by the user after the operating system install on 2004-08-19:

| Installed (UTC) | Program | Relevance |
|---|---|---|
| 2004-08-20 15:05:09 | Anonymizer Bar 2.0 | Anonymous browsing |
| 2004-08-20 15:05:58 | Cain & Abel v2.5 beta45 | Password recovery / network sniffing |
| 2004-08-20 15:07:25 | Faber Toys v2.4 | Utility suite |
| 2004-08-20 15:08:19 | Forté Agent | Usenet newsreader |
| 2004-08-20 15:09:02 / 15:09:03 | CuteFTP, CuteHTML | FTP client and HTML editor |
| 2004-08-20 15:10:04 | mIRC | IRC client |
| 2004-08-20 15:12:43 | Powertoys for Windows XP | Microsoft utilities |
| 2004-08-20 15:13:08 | 123 Write All Stored Passwords | Password-revealing utility |
| 2004-08-25 15:56:11 | Look@LAN 2.50 Build 29 | Network scanner |
| 2004-08-27 15:12:15 | Network Stumbler 0.4.0 | Wireless network discovery |
| 2004-08-27 15:15:19 | WinPcap 3.01 alpha | Packet capture driver |
| 2004-08-27 15:29:19 | Ethereal 0.10.6 | Packet sniffer |

The remaining entries (Outlook Express, NetMeeting, IE components, PCHealth and so on) date from the original Windows install on 2004-08-19.

## 10. E-mail, Newsgroup and IRC Activity

Forté Agent was found under `Program Files/Agent/` and its `Documents and Settings/Mr. Evil/Desktop/Tools/Agent.lnk` shortcut. Its configuration file (inode 11406) was read directly:

```
fls -rF -o 63 SCHARDT.dd | grep -i 'agent' | head
icat -o 63 SCHARDT.dd 11406 | more
```

| AGENT.INI field | Value |
|---|---|
| FullName | "Mr Evil" |
| EMailAddress / UserName / SMTPUserName | whoknowsme@sbcglobal.net |
| SavePassword / SMTPSavePassword | 1 (stored in the file in encoded form) |

Outlook Express under the Mr. Evil identity holds many newsgroup databases: alt.2600.* (cardz, codez, crackz, hackerz, phreakz, programz, moderated), alt.binaries.hacking.* (beginner, computers, utilities, websites), alt.hacking, alt.dss.hack, alt.nl.binaries.hack, alt.stupidity.hackers.malicious and free.binaries.hacking.* groups, plus Inbox, Outbox and Deleted Items. Strings in `alt.2600.cardz.dbx` show the news server **news.dallas.sbcglobal.net**.

mIRC (shortcut on the Mr. Evil desktop under Tools) has channel logs for #Elite.Hackers, #CyberCafe, #Chataholics, #LuxShell, #ushells, #mp3xserv, #houston, #funny and m5star (UnderNet), #evilfork and #ISO-WAREZ (EFnet), and #thedarktower (AfterNET). `mirc.ini` (inode 10080) shows `userid=Mrevil`, user "Mini Me", and the Undernet Los Angeles server on port 6660.

## 11. Captured Network Traffic

A file named `interception` sits in the Mr. Evil profile folder. It was identified and read with tshark:

```
file '/mnt/loop/Documents and Settings/Mr. Evil/interception'
tshark -r '/mnt/loop/Documents and Settings/Mr. Evil/interception' -Y http.request -T fields -e http.user_agent -e http.host | sort -u
```

| Property | Value |
|---|---|
| File type | pcap capture file, version 2.4, Ethernet, capture length 65535 |
| User agent | Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320) |
| Hosts requested | mobile.msn.com, www.passportimages.com, login.passport.com, login.passport.net |

The traffic comes from a Windows CE Pocket PC browsing MSN Mobile and logging in through Microsoft Passport, not from the Windows XP laptop's own Internet Explorer. Together with Network Stumbler, WinPcap, Ethereal and a wireless card installed on 2004-08-27, this indicates wireless sniffing of other people's traffic.

## 12. Recycle Bin and Deleted Files

```
ls '/mnt/loop/RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003'
rifiuti2 '/mnt/loop/RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/INFO2'
fls -rFd -o 63 SCHARDT.dd | wc -l
```

The Recycle Bin belongs to SID -1003 (Mr. Evil) and holds Dc1.exe–Dc4.exe, desktop.ini and INFO2. rifiuti2 (time zone UTC) mapped them to the original paths:

| Index | Deleted (UTC) | Original file | Size (bytes) | Still in bin |
|---|---|---|---|---|
| 1 | 2004-08-25 16:18:25 | Desktop\lalsetup250.exe | 2,160,128 | Yes |
| 2 | 2004-08-27 15:12:30 | Desktop\netstumblerinstaller_0_4_0.exe | 1,325,056 | Yes |
| 3 | 2004-08-27 15:15:26 | Desktop\WinPcap_3_01_a.exe | 442,880 | Yes |
| 4 | 2004-08-27 15:29:58 | Desktop\ethereal-setup-0.10.6.exe | 8,460,800 | Yes |

A further 365 deleted file entries were counted in the filesystem with `fls -rFd`.

## 13. Malware Scan

ClamAV 1.4.5 was installed (340,942 signatures) and run against the mounted image:

```
sudo apt-get install clamav
clamscan --help
clamscan -r -i '/mnt/loop'
```

The scan ran 2026-08-26 14:30:00–14:30:06 but reported **0 files scanned**: the command had been pasted with typographic dashes and quotes, so clamscan treated `-r`, `-i` and `/mnt/loop` as files that do not exist. The scan is therefore inconclusive and must be repeated with plain ASCII characters (`clamscan -r -i /mnt/loop`).

## Conclusion – Is Greg Schardt a hacker?

**On the evidence in this image, yes: the computer belonged to Greg Schardt, who used it under the alias "Mr. Evil", and it was set up and used for hacking and network eavesdropping.** The reasoning:

- **Attribution:** Windows registered owner and the Look@LAN registration are Greg Schardt; the only user account is Mr. Evil (15 logins, administrator); the Yahoo registration form shows Greg Schardt with ID mrevil2000; Forté Agent is set to "Mr Evil"; the workgroup is named EVIL.
- **Tools:** Cain & Abel, Look@LAN, Network Stumbler, WinPcap, Ethereal, 123 Write All Stored Passwords and Anonymizer Bar were installed within days of each other, with the last four network tools installed on 2004-08-27 and their installers deleted to the Recycle Bin within minutes.
- **Activity:** Outlook Express subscribed to dozens of hacking, cracking and phreaking newsgroups, and mIRC logs include #Elite.Hackers and #ISO-WAREZ.
- **Interception:** the `interception` pcap holds another person's mobile browsing and Passport login traffic, captured with a wireless card and sniffer.

**Limitations:** the disk alone shows the account and software, not who was physically at the keyboard; several of these tools are dual-use and legal on their own; and no victim system or stolen credentials are identified in the files examined. The conclusion is therefore that the evidence strongly supports Schardt (Mr. Evil) as the user and as engaging in hacking activity, and a court-level finding would need corroboration such as network logs or witness evidence.

## Reconstructed Timeline (2004, UTC)

| Time | Event | Source |
|---|---|---|
| Aug 19 16:59:24 | Administrator and Guest accounts created | SAM |
| Aug 19 17:07:19 | Xircom Ethernet/modem card registered | NetworkCards |
| Aug 19 22:48:27 | Windows XP install date | winver |
| Aug 19 23:03:54 | Mr. Evil account created (administrator) | SAM |
| Aug 20 15:05–15:13 | Anonymizer, Cain & Abel, Agent, CuteFTP, mIRC, password tool installed | Uninstall key |
| Aug 25 15:56:11 | Look@LAN 2.50 installed | Uninstall key |
| Aug 25 16:18:25 | lalsetup250.exe moved to Recycle Bin | INFO2 |
| Aug 27 15:08:23 | Mr. Evil last login (15th) | SAM |
| Aug 27 15:12:15–15:12:30 | Network Stumbler installed; installer deleted | Uninstall key / INFO2 |
| Aug 27 15:15:19–15:15:26 | WinPcap installed; installer deleted | Uninstall key / INFO2 |
| Aug 27 15:29:19–15:29:58 | Ethereal installed; installer deleted | Uninstall key / INFO2 |
| Aug 27 15:31:44 | Compaq WL110 wireless card key written | NetworkCards |
| Aug 27 15:46:23 | Mr. Evil profile last written | ProfileList |
| Aug 27 15:46:33 | System shutdown | shutdown plugin |

## Key Tools Used

| Tool | Purpose |
|---|---|
| wget / cat / md5sum | Image download, reassembly and hashing |
| mmls / fls / icat (Sleuth Kit) | Partition layout, file listing and extraction |
| RegRipper | winver, timezone, compname, shutdown, samparse, samparse_tln, profilelist, networkcards, uninstall |
| evtparse.pl | SysEvent.Evt to TLN timeline |
| losetup / mount | Read-only mount of the image |
| strings / grep / egrep / comm | Keyword, e-mail, IP and MAC searches |
| tshark | Reading the intercepted pcap |
| rifiuti2 | Recycle Bin INFO2 parsing |
| clamscan | Malware scan (needs to be repeated) |

## Forensic Notes

- The registered owner, the Mr. Evil account, the Yahoo registration, the Agent profile and the Look@LAN registration all point to the same person, but attribution should still be corroborated outside the disk.
- Windows XP stores times in UTC in the registry; Kali's `date` printed EDT, so the TLN epoch conversion (1093619303 = 15:08:23 UTC) should be reported in UTC.
- The Kali host clock reads 2026, while all evidence dates are 2004; the 2026 dates only describe when the lab was performed.
- Segments SCHARDT.006 and .007 hash identically; the assembled SCHARDT.dd MD5 should be checked against the NIST published value and recorded for chain of custody. A SHA-256 should also be recorded.
- Several commands failed because of typing or paste problems (uppercase filename, `ls -l` with a typographic dash, a regex left with an open quote, `grep -I` skipping binary files). Results were only used after the corrected commands succeeded.
- The ClamAV scan scanned 0 files and cannot be used to claim the image is clean or infected.
- The "Last Login" and "Login Count" values in the SAM can be reset or altered; they are consistent with the profile and shutdown timestamps here.
- The image was mounted read-only (`--read-only`), and all extraction used copies (`icat`) so the original SCHARDT.dd was not modified.

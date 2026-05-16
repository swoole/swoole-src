
# PHP Windows extension build and test tools

## In-action usage

``` yaml
      - name: Build Some extension
        uses: "./.github/workflows/winext" # if this thing is here or
        uses: "swow/some-action@somebranch" # if this re-released in separate repo (TODO)
        with:
          ext-path: .
          tools-path: whatever
          conf-args: --enable-yourext-debug
          ext-name: yourext
          deps: openssl,libcurl,libssh2,zlib,nghttp2
```

### "with" args

#### ext-path

Any path your extension source code (config.w32) located in.

For Swow, Swow's config.w32 is located in `<project dir>/ext`, so it will be `./ext` for Swow.

For Parallel (at this time), it's config.w32 is in root dir of project, so use `.` or keep it empty.

Default is '.'

#### tools-path

Directory for tools downloaded, default is `C:\tools\phpdev`

#### conf-args

configure.bat args, like `--enable-swow-curl`

Default is empty

#### ext-name

Necessary

Extension name for installing, like `swow`, needs match what is set in config.w32.

#### max-try

Max download retry times, default is `3`

#### deps

Comma splited list for dependencies can be downloaded at `https://downloads.php.net/~windows/php-sdk/deps/<sdk version>/<arch>/<depname>-<version>-<sdk version>-<arch>.zip`

deps will be downloaded into `<tools-path>\deps`, this dir can be cached for faster build.

Default is empty

#### install

If we install the built extension, '0' for not install, '1' for install.

Default is '1'

#### phpver

PHP version used for extension build, in format `<maj>.<min>` like '8.0' or you can use 'php' for auto detect php in %PATH%.

Default is 'php'

#### phpts

If we use thread safe version of PHP (and SDK) downloaded and used, '0' for nts, '1' for ts.

Default is '0'

#### phparch

Architecture for PHP (and SDK) downloaded and used, yet 'x64' is only supported option yet ('x86' may also work, but is not proved).

Default is 'x64'

#### staging-deps

If we use 'staging' version deps, for master branch PHP extension build, '0' for not, '1' for using.

Default is '0'

#### fix-pickle

If we fix pickle.h for definitions duplicates to omit MSVC warnings, '0' for not, '1' for using.

Default is '1'

## Standalone usage

All utilities is wrote in powershell and can be invoke in ps shell.

### Shared args

All utilities have same usage for these args

#### MaxTry

```powershell
.\path\to\any.ps1 -MaxTry <int>
```

Optional.

Specify max retry for downloads, default is 3

#### ToolsPath

```powershell
.\path\to\any.ps1 -ToolsPath <string>
```

Optional.

Specify download target dir for downloads, default is 'C:\tools\phpdev'

### Common args

Some utilities have similar usage for these args

#### PhpVer

```powershell
.\path\to\some.ps1 -PhpVer <string>
```

At most time this option is optional.

Specify php version is used, in `<maj>.<min>` format like '8.0'

#### PhpVCVer

```powershell
.\path\to\some.ps1 -PhpVCVer <string>
```

At most time this option is optional.

Specify VC toolset version for PHP is used, needs to be uppercase, like 'VS16'.

#### PhpArch

```powershell
.\path\to\some.ps1 -PhpArch <string>
```

At most time this option is optional.

Specify PHP arch is used, like 'x64'.

#### PhpTs

```powershell
.\path\to\some.ps1 -PhpTs <bool>
```

At most time this option is optional.

If we use thread safe version.

#### DryRun

```powershell
.\path\to\some.ps1 -PhpTs <bool>
```

This option is optional.

Dry run only, donot do action,

#### ExtName

```powershell
.\path\to\some.ps1 -ExtName <string>
```

Extension name, needs match what it is setted in config.w32.

#### ExtPath

```powershell
.\path\to\some.ps1 -ExtPath <string>
```

Extension path, default is '.'

### getphp.ps1

```powershell
.\path\to\getphp.ps1 `
    -PhpVer <string> `
    [-PhpTs <bool>] `
    [-PhpVCVer <string>] `
    [-PhpArch <string>] `
    [-DryRun <bool>] `
    [-MaxTry <int>] `
    [-ToolsPath <string>]
```

Fetch specified PHP for futher use.

At lease `<maj>.<min>` format PhpVer argument is needed for determining which varient to be downloaded.

### deps.ps1

```powershell
.\path\to\deps.ps1 `
    -DllDeps <list of string<deps>> `
    -PhpVer "" `
    [-PhpBin <string>] `
    [-DryRun <bool>] `
    [-Staging <bool>] `
    [-MaxTry <int>] `
    [-ToolsPath <string>]

.\path\to\deps.ps1 `
    -DllDeps <list of string<deps>> `
    -PhpVer <string> `
    -PhpTs <bool> `
    -PhpVCVer <string> `
    -PhpArch <string> `
    [-DryRun <bool>] `
    [-Staging <bool>] `
    [-MaxTry <int>] `
    [-ToolsPath <string>]
```

Fetch deps from https://downloads.php.net/~windows for futher use.

If PHP version args is not specified, it will use PhpBin arg (default is "php") to find php version and varient.

#### Staging

If we use staging version deps.

### devpack.ps1

```powershell
.\path\to\devpack.ps1 `
    -PhpVer "" `
    [-PhpBin <string>] `
    [-DryRun <bool>] `
    [-MaxTry <int>] `
    [-ToolsPath <string>]

.\path\to\devpack.ps1 `
    -PhpVer <string> `
    -PhpTs <bool> `
    -PhpVCVer <string> `
    -PhpArch <string> `
    [-DryRun <bool>] `
    [-MaxTry <int>] `
    [-ToolsPath <string>]
```

Fetch development pack from https://downloads.php.net/~windows for futher use.

If PHP version args is not specified, it will use PhpBin arg (default is "php") to find php version and varient.

### devpack_master.ps1

```powershell
.\path\to\devpack_master.ps1 `
    [-PhpTs <bool>] `
    [-PhpVCVer <string>] `
    [-PhpArch <string>] `
    [-Release <string>] `
    [-MaxTry <int>] `
    [-ToolsPath <string>]

```

Fetch development pack from shivammathur/php-builder-windows for futher use.

Needs setup-php for windows using master version like

```yaml
    - name: Setup PHP
        uses: shivammathur/setup-php@master
        with:
          php-version: '8.2' # at this time 8.1 is latest release version
```

#### Release

Release name, yet only 'master' is used.

### build.ps1

```powershell
.\path\to\build.ps1 `
    -ExtName <string> `
    [-ExtPath <string>] `
    [-ToolsPath <string>] `
    [... <ExtraArgs>]
```

Build extension, needs devpack already setted up.

Example: `.\path\to\build.ps1 -ExtName Swow -ExtPath ./ext -ToolsPath C:\phpdev --enable-swow-debug --enable-swow-asan`

#### ExtraArgs

Extra arguments used for configure.bat

### install.ps1

```powershell
.\path\to\install.ps1 `
    -ExtName <string> `
    [-ExtPath <string>] `
    [-PhpBin <string>] `
    [-Enable <bool>]
```

Install built extension into php extension dir, use PhpBin arg (default is 'php' in %PATH%) to specify which php is used.

#### Enable

If add `extension=<ExtName>` into php.ini, default is $false.

### release.ps1

```powershell
.\path\to\install.ps1 `
    -Token <string> `
    -Repo <string> `
    -TagName <string> `
    -body <string> `
    [-prerelease <bool>] `
    [-draft <bool>]
```

Create a github release

#### Token

github token used

#### Repo

repository in format `<user or organization>/<project name>`.

#### TagName

Release tag name like 'v0.1.2-prealpha3'

#### body

Release note, in markdown

#### prerelease

This is a prerelease, default is $false

#### draft

This is a draft, default is $true

## License

This project (standalone project or files located in swow .github/workflows/winext) is licensed under MIT License

```plain
Copyright 2021 Yun Dou <dixyes@gmail.com>
Copyright 2021 twosee <twosee@php.net>
Copyright 2021 Swow Contributers

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

# RESTBL  [![Downloads](https://img.shields.io/github/downloads/MasterBubbles/restbl/total)](https://github.com/MasterBubbles/restbl/releases)
RESTBL is a simple rewrite of [dt12345's tool](https://github.com/dt-12345/totktools/blob/master/dist/RESTBL%20Tool.md) to work with command-line arguments as well as including an improved GUI.

This is a tool for working with and merging RESTBL files in *Tears of the Kingdom*. RESTBL files are used by the game's resource system to decide how much memory it should allocate for each file. Each entry in a RESTBL file contains a CRC32 hash of the corresponding file's path and its allocation size. The allocated size as listed in the RESTBL is not exactly equal to the size of the file, it is slightly larger.

When developing or using mods, the RESTBL oftens becomes an issue as changes to file sizes may lead to the existing RESTBL entry becoming too small. This will result in the game crashing when it attempts to load in said resource. As a result, many mods come with edited RESTBL files, tailored for that specific mod. The issue arises when you have multiple mods all requiring RESTBL edits. This tool aims to solve that issue by automating the process without the need for external changelog files (such as YAML patches or .rcl files).

### Important notes
When you open the tool (or run it from the command line), it will check for a config.json file in the folder `%LocalAppData%\TotK` (this is the same configuration file as [NX-Editor](https://github.com/NX-Editor), which should contain the path to a RomFS dump of the game). If that file doesn't exist, it will prompt you to enter the path to a dump, which should at least include `Pack/ZsDic.pack.zs`.

Additionally, the tool requires a file called `checksums.bin` (also located in `%LocalAppData%\TotK`). If that file doesn't exist when you run the executable, it will automatically download it from [this GitHub link](https://github.com/MasterBubbles/restbl/raw/master/checksums.bin).

## GUI Usage
Here is what each options are for at the top:
- Compress: this will compress the output resource tables with ZSTD (enabled by default)
- Use existing RESTBL: this will generate changelogs from existing resource tables rather than calculate new values
- Delete existing RESTBL: this will automatically delete resource tables in all mods for the selected version (to avoid conflicts when merging)
- Use checksums: this will check if a file is vanilla or edited, in order to avoid calculating new values for unedited files (enabled by default)
- Verbose: this will display all modded files detected in the command prompt (makes the tool slower, disabled by default)
- Version: this is the version of the game to generate a resource table for (this should be the version you use)
- Patch existing RESTBL: check this if you want to patch an existing resource table rather than generate a new one 

The GUI is separated in 4 sections, depending on which action you would like to perform:

<img src="https://raw.githubusercontent.com/MasterBubbles/restbl/master/screenshots/restbl.png" width="50%" height="50%">

### Calculate RESTBL from Mod(s)
This section is probably the only one you are interested in. It's very simple and straight forward, you need to select the path to a folder containing one or multiple mods. This should be a path so that one or multiple folders like `[selected_path]/[mod_name]/romfs` exists (like your mod folder for Ryujinx or Yuzu).

**Example:**
```
 Selected Folder/
    ├── Mod 1/
    │   └── romfs
    ├── Mod 2/
    │   └── romfs
    └── Mod 3/
        └── romfs
```

### Merge RESTBLs
This section is for merging 2 resource tables. You can use 2 different versions, the version from file 1 will be used for the output file.

### Generate changelog
This section is needed only if you want to generate a changelog containing the list of edits on a selected resource table. You can choose betwen 3 possible changelog formats: JSON, RCL or YAML

### Apply patches
This section is useful if you want to apply all JSON, RCL and YAML patches in a folder to a selected RESTBL file.

### Calculate RESTBL from Single Mod
This will generate a resource table for a single mod (select the folder containing `romfs`). It will automatically be generated in the mod's folder under `romfs/System/Resource`.
<br><br>

## CLI Usage
To use the tool, simply run `restbl.exe` from the command line using `restbl -h` to get all available options. There are four options to choose from: merge-mods, merge-restbl, generate-changelog, apply-patches

### merge-mods
This option will analyze the provided mod directories and automatically generate an edited RESTBL file.

Using the `--compress` option will compress the generated RESTBL file with Zstd compression.

Using the `--use-existing-restbl` option will search each mod for an existing RESTBL file. If the file exists, that file will be used for that mod instead of analyzing the directory.

Using the `--delete-existing-restbl` option will automatically delete any existing RESTBL files present in the mod(s) during analysis to prevent any potential file conflicts. This option is compatible with the `--use-existing-restbl` option.

Using the `--use-checksums` option will compare each file in the mod with the unmodified file by comparing a SHA-256 hash of the file. This avoids creating unnecessary RESTBL entries for unmodified files that may be present in the mod.

When using `merge-mods`, the argument `--mod-path C:\Path\to\mods` is required. This should be the folder so that the path `[selected_path]/[mod_name]/romfs` exists (can contain 1 or multiple mods).

> restbl.exe --action merge-mods --use-checksums --compress --mod-path "C:\Users\username\AppData\Roaming\Ryujinx\mods\contents\0100f2c0115b6000" --version 120

> restbl.exe -a merge-mods  -cs -c -m "C:\Users\username\AppData\Roaming\Ryujinx\mods\contents\0100f2c0115b6000" -ver 120

### - merge-restbl
This option will create a merged RESTBL file from the two provided RESTBL files. Similar to the previous option, using `--compress` will compress the generated RESTBL file with Zstd compression.

> restbl.exe --action merge-restbl  --compress --restbl-path0 "C:\path\to\file1\ResourceSizeTable.Product.120.rsizetable.zs" --restbl-path1 "C:\path\to\file2\ResourceSizeTable.Product.120.rsizetable.zs"

> restbl.exe -a merge-restbl  -c -r0 "C:\path\to\file1\ResourceSizeTable.Product.120.rsizetable.zs" -r1 "C:\path\to\file2\ResourceSizeTable.Product.120.rsizetable.zs"


### - generate-changelog
This option will generate a changelog in the format of your choice from the selected RESTBL file.

> restbl.exe --action generate-changelog --log-restbl-path "C:\path\to\file\ResourceSizeTable.Product.112.rsizetable.zs" --format rcl

> restbl.exe -a generate-changelog -l "C:\path\to\file\ResourceSizeTable.Product.112.rsizetable.zs" -f rcl


### - apply-patches
This option will apply all JSON, RCL and YAML patches in a folder to the selected RESTBL file.

> restbl.exe --action apply-patches  --compress --patch-restbl "C:\path\to\file\ResourceSizeTable.Product.121.rsizetable.zs" --patches-path "C:\path\to\folder\containing\json_rcl_yaml_patches"

> restbl.exe -a apply-patches  -c -p "C:\path\to\file\ResourceSizeTable.Product.121.rsizetable.zs" -pp "C:\path\to\folder\containing\json_rcl_yaml_patches"


### single-mod
This mode will analyze the provided mod directory and automatically generate an edited RESTBL file.

When using this mode, the resource table will automatically be generated within the mod's folder under `romfs/System/Resource`

It uses the exact same arguments as `merge-mods`, except that `--mod-path` requires the path to a single mod containing a `romfs` folder

> restbl.exe --action single-mod --use-checksums --compress --mod-path "C:\Users\username\AppData\Roaming\Ryujinx\mods\contents\0100f2c0115b6000\ModName" --version 112

> restbl.exe -a merge-mods  -cs -c -m "C:\Users\username\AppData\Roaming\Ryujinx\mods\contents\0100f2c0115b6000\ModName" -ver 112


## CLI Help
```
RESTBL Tool

usage: restbl.exe [-h] -a {action} [-c] [-v] [-cs] [-m MOD_PATH] [-r RESTBL_PATH] [-ver VERSION]
                  [-u] [-d] [-r0 RESTBL_PATH0] [-r1 RESTBL_PATH1] [-l LOG_RESTBL_PATH]
                  [-f {json,rcl,yaml}] [-p PATCH_RESTBL] [-pp PATCHES_PATH]

RESTBL Tool

options:
  -h, --help            show this help message and exit
  -a, --action {merge-mods,merge-restbl,generate-changelog,apply-patches,single-mod}
                        Action to perform
  -c, --compress        Compress the output
  -v, --verbose         Print the list of edited files from mods
  -cs, --use-checksums  [Recommended] Use checksums
  -m MOD_PATH, --mod-path MOD_PATH
                        Mandatory for actions "merge-mods" and "single-mod"
  -r RESTBL_PATH, --restbl-path RESTBL_PATH
                        (Optional) Path to a RESTBL file to patch when calculating entries for mods
  -ver VERSION, --version VERSION
                        (Optional) TotK version - default: 121

merge-mods:
  -u, --use-existing-restbl
                        (Optional) Use existing RESTBL
  -d, --delete-existing-restbl
                        (Optional) Delete existing RESTBL

merge-restbl:
  -r0 RESTBL_PATH0, --restbl-path0 RESTBL_PATH0
                        (Mandatory) Path to the first RESTBL file to merge
  -r1 RESTBL_PATH1, --restbl-path1 RESTBL_PATH1
                        (Mandatory) Path to the second RESTBL file to merge

generate-changelog:
  -l LOG_RESTBL_PATH, --log-restbl-path LOG_RESTBL_PATH
                        (Mandatory) Path to the RESTBL file for generating changelog
  -f {json,rcl,yaml}, --format {json,rcl,yaml}
                        (Mandatory) Format of the changelog

apply-patches:
  -p PATCH_RESTBL, --patch-restbl PATCH_RESTBL
                        (Mandatory) Path to the RESTBL file to patch
  -pp PATCHES_PATH, --patches-path PATCHES_PATH
                        (Mandatory) Path to the folder containing patches (rcl, yaml, json)
```

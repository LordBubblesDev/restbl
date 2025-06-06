from icon import images
from utils import *
import zstandard as zs
import yaml
from collections import defaultdict
from functools import lru_cache
import numpy as np
import xxhash
import sarc
import os
import binascii
import json
import sys
import argparse
import time
import zstd

def welcome():
    return """
              / \\\\
             /   \\\\
            /_____\\\\
           /\\\\    /\\\\
          /  \\\\  /  \\\\
         /____\\\\/____\\\\
   __________________________

   - TotK RESTBL Calculator -
   __________________________
"""
# For pyinstaller relative paths
def get_correct_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

DEV_MODE = False
version = None

game_file_extensions = [
    '.ainb', '.asb', '.baatarc', '.baev', '.bagst', '.bars', '.bcul', '.beco', 
    '.belnk', '.bfarc', '.bfevfl', '.bfres', '.bfsha', '.bgyml', '.bhtmp', '.bkres', 
    '.blal', '.blarc', '.blwp', '.bnsh', '.bntx', '.bphcl', '.bphhb', '.bphnm', 
    '.bphsc', '.bphsh', '.bslnk', '.bstar', '.byml', '.cai', '.casset.byml', 
    '.chunk', '.crbin', '.cutinfo', '.dpi', '.genvb', '.jpg', '.mc', '.pack', 
    '.png', '.quad', '.sarc', '.tscb', '.txt', '.txtg', '.vsts', '.wbr', '.zs'
]

class Restbl:
    def __init__(self, filepath): # Accepts both compressed and decompressed files
        if os.path.splitext(filepath)[1] in ['.zs', '.zstd']:
            decompressor = zs.ZstdDecompressor()
            with open(filepath, 'rb') as f:
                compressed = f.read()
                data = decompressor.decompress(compressed)
                filepath = os.path.splitext(filepath)[0]
        else:
            with open(filepath, 'rb') as f:
                data = f.read()
        
        self.stream = ReadStream(data)
        self.filename = filepath
        self.game_version = os.path.basename(filepath).split('.')[2]
        self.hashmap = {}

        self.magic = self.stream.read(6).decode('utf-8')
        assert self.magic == "RESTBL", f"Invalid file magic, expected 'RESTBL' but got '{self.magic}'"
        self.version = self.stream.read_u32()
        assert self.version == 1, f"Invalid version, expected v1 but got v{self.version}"
        self.string_size = self.stream.read_u32()
        self.hash_count = self.stream.read_u32()
        self.collision_count = self.stream.read_u32()

        self.hash_table = {}
        self.collision_table = {}

        for i in range(self.hash_count):
            self.ReadHashEntry()
        
        for i in range(self.collision_count):
            self.ReadCollisionEntry()
    
    def ReadHashEntry(self):
        hash = self.stream.read_u32()
        self.hash_table[hash] = self.stream.read_u32()
        return
    
    def ReadCollisionEntry(self):
        filepath = self.stream.read_string()
        if len(filepath) > self.string_size:
            raise ValueError("Collision table filepath string was too large")
        self.stream.read(self.string_size - len(filepath) - 1)
        self.collision_table[filepath] = self.stream.read_u32()
        return

    def Reserialize(self, output_dir=''):
        if os.path.exists(output_dir):
            os.makedirs(output_dir)
        with open(os.path.join(output_dir, self.filename), 'wb') as outfile:
            self.buffer = WriteStream(outfile)
            self.buffer.write("RESTBL".encode('utf-8'))
            self.buffer.write(u32(self.version))
            self.buffer.write(u32(self.string_size))
            self.buffer.write(u32(len(self.hash_table)))
            self.buffer.write(u32(len(self.collision_table)))
            # Hash table is sorted by hash for fast lookup
            self.hash_table = dict(sorted(self.hash_table.items()))
            # Collision table is sorted by name for fast lookup
            self.collision_table = dict(sorted(self.collision_table.items()))
            for hash in self.hash_table:
                self.buffer.write(u32(hash))
                self.buffer.write(u32(self.hash_table[hash]))
            for name in self.collision_table:
                string = name.encode('utf-8')
                while len(string) != self.string_size:
                    string += b'\x00'
                self.buffer.write(string)
                self.buffer.write(u32(self.collision_table[name]))

    def AddEntry(self, path, size):
        hash = binascii.crc32(path.encode('utf-8'))
        if hash not in self.hash_table:
            self.hash_table[hash] = size
        else:
            self.collision_table[path] = size
    
    def DeleteEntry(self, path):
        hash = binascii.crc32(path.encode('utf-8'))
        if path in self.collision_table:
            del self.collision_table[path]
        elif hash in self.hash_table:
            del self.hash_table[hash]
        else:
            raise ValueError("Entry not found")
        
    def AddByHash(self, hash, size):
        self.hash_table[hash] = size
    
    def DeleteByHash(self, hash):
        try:
            del self.hash_table[hash]
        except KeyError:
            raise KeyError("Entry not found")
    
    # Generates mapping of CRC32 hashes to filepaths
    def _GenerateHashmap(self, paths=[]):
        if paths == []:
            version = os.path.basename(self.filename).split('.')[2]
            string_list = "string_lists/" + version.replace('.', '') + ".txt"
            string_list = get_correct_path(string_list)
            paths = []
            with open(string_list, 'r') as strings:
                for line in strings:
                    paths.append(line[:-1])
        for path in paths:
            if path not in self.collision_table:
                self.hashmap[binascii.crc32(path.encode('utf-8'))] = path
        return self.hashmap

    # Returns all modified entries
    @staticmethod
    def _DictCompareChanges(edited, original):
        return {k: edited[k] for k in edited if k in original and edited[k] != original[k]}
    
    # Returns all entries not present in the modified version
    @staticmethod
    def _DictCompareDeletions(edited, original):
        return {k: original[k] for k in original if k not in edited}
    
    # Returns all entries only present in the modified version
    @staticmethod
    def _DictCompareAdditions(edited, original):
        return {k: edited[k] for k in edited if k not in original}

    # Merges the changes to the hash table and collision table into one dictionary
    # Function should be one of the DictCompare functions above
    def _GetCombinedChanges(self, original, function):
        changes_hash = function(self.hash_table, original["Hash Table"])
        changes_collision = function(self.collision_table, original["Collision Table"])
        changes = {}
        for hash in changes_hash:
            string = self._TryGetPath(hash, self.hashmap)
            changes[string] = changes_hash[hash]
        changes = changes | changes_collision
        return changes

    # Attempts to get the filepath from the hash and returns the hash if not found
    @staticmethod
    def _TryGetPath(hash, hashmap):
        if hash in hashmap:
            return hashmap[hash]
        else:
            return hash

    # Changelog comparing to the vanilla file
    def GenerateChangelog(self):
        original_filepath = "restbl/ResourceSizeTable.Product." + self.game_version + ".rsizetable.json"
        original_filepath = get_correct_path(original_filepath)
        with open(original_filepath, 'r') as file:
            original = json.load(file, object_pairs_hook=lambda d: {int(k) if k.isdigit() else k: v for k, v in d})
        changes = self._GetCombinedChanges(original, self._DictCompareChanges)
        additions = self._GetCombinedChanges(original, self._DictCompareAdditions)
        deletions = self._GetCombinedChanges(original, self._DictCompareDeletions)
        changelog = {"Changes" : changes, "Additions" : additions, "Deletions" : deletions}
        return changelog

    # RCL files for NX-Editor
    def GenerateRcl(self, filename=''):
        changelog = self.GenerateChangelog()
        if self.hashmap == {}:
            self._GenerateHashmap()
        if filename == "":
            filename = "changes.rcl"
        with open(filename, 'w') as rcl:
            for change in changelog["Changes"]:
                string = self._TryGetPath(change, self.hashmap)
                if type(string) == int:
                    string = hex(string)
                string = str(string)
                rcl.write('* ' + string + ' = ' + str(changelog["Changes"][change]) + '\n')
            for change in changelog["Additions"]:
                string = self._TryGetPath(change, self.hashmap)
                if type(string) == int:
                    string = hex(string)
                string = str(string)
                rcl.write('+ ' + string + ' = ' + str(changelog["Additions"][change]) + '\n')
            for change in changelog["Deletions"]:
                string = self._TryGetPath(change, self.hashmap)
                if type(string) == int:
                    string = hex(string)
                string = str(string)
                rcl.write('- ' + string + '\n')

    # Necessary to apply RCL files as patches
    def GenerateChangelogFromRcl(self, rcl_path):
        changelog = {"Changes" : {}, "Additions" : {}, "Deletions" : {}}
        with open(rcl_path, 'r') as rcl:
            for line in rcl:
                entry = line.split(" = ")
                match line[0]:
                    case "*":
                        changelog["Changes"][entry[0].lstrip("*+- ").rstrip("= ")] = int(entry[1])
                    case "+":
                        changelog["Additions"][entry[0].lstrip("*+- ").rstrip("= ")] = int(entry[1])
                    case "-":
                        changelog["Deletions"][entry[0].lstrip("*+- ").rstrip("= ")] = 0
        return changelog

    def GenerateYamlPatch(self, filename=''):
        changelog = self.GenerateChangelog()
        if filename == "":
            filename = "changes.yml"
        if self.hashmap == {}:
            self._GenerateHashmap()
        patch = {}
        for change in changelog["Changes"]:
            patch[self._TryGetPath(change, self.hashmap)] = changelog["Changes"][change]
        for addition in changelog["Additions"]:
            patch[self._TryGetPath(addition, self.hashmap)] = changelog["Additions"][addition]
        for deletion in changelog["Deletions"]:
            patch[self._TryGetPath(deletion, self.hashmap)] = 0
        with open(filename, 'w') as yaml_patch:
            yaml.dump(patch, yaml_patch, allow_unicode=True, encoding='utf-8', sort_keys=True)
    
    # Necessary to apply YAML patches
    # YAML patches don't appear to support entry deletion
    def GenerateChangelogFromYaml(self, yaml_path):
        changelog = {"Changes" : {}, "Additions" : {}, "Deletions" : {}}
        with open(yaml_path, 'r') as yml:
            patch = yaml.safe_load(yml)
        original_filepath = "restbl/ResourceSizeTable.Product." + self.game_version + ".rsizetable.json"
        original_filepath = get_correct_path(original_filepath)
        with open(original_filepath, 'r') as file:
            original = json.load(file, object_pairs_hook=lambda d: {int(k) if k.isdigit() else k: v for k, v in d})
        for change in patch:
            hash = binascii.crc32(change.encode('utf-8'))
            if hash in original["Hash Table"] or change in original["Collision Table"]:
                changelog["Changes"][change] = patch[change]
            else:
                changelog["Additions"][change] = patch[change]
        return changelog

    def ApplyChangelog(self, changelog):
        # Pre-calculate hashes
        changes = {binascii.crc32(k.encode('utf-8')) if isinstance(k, str) else k: v for k, v in changelog["Changes"].items()}
        additions = {binascii.crc32(k.encode('utf-8')) if isinstance(k, str) else k: v for k, v in changelog.get("Additions", {}).items()}
        deletions = {binascii.crc32(k.encode('utf-8')) if isinstance(k, str) else k for k in changelog.get("Deletions", {})}

        # Apply changes and additions
        self.hash_table = defaultdict(int, {**self.hash_table, **changes, **additions})

        # Remove deletions
        self.hash_table = {k: v for k, v in self.hash_table.items() if k not in deletions}

        # Print added entries
        for k in set(changes.keys()).difference(self.hash_table.keys()):
            print(f"{k} was added as it was not an entry in the provided RESTBL")
    
    def ApplyRcl(self, rcl_path):
        changelog = self.GenerateChangelogFromRcl(rcl_path)
        self.ApplyChangelog(changelog)
    
    def ApplyYamlPatch(self, yaml_path):
        changelog = self.GenerateChangelogFromYaml(yaml_path)
        self.ApplyChangelog(changelog)
    
    # Merges RCL/YAML patches in a single directory into one changelog
    def MergePatches(self, patches_folder):
        patches = [file for file in os.listdir(patches_folder) if os.path.splitext(file)[1] in ['.rcl', '.yml', '.yaml']]
        changelogs = []
        for patch in patches:
            ext = os.path.splitext(patch)[1]
            if ext in ['.yml', '.yaml']:
                changelogs.append(self.GenerateChangelogFromYaml(os.path.join(patches_folder, patch)))
            else:
                changelogs.append(self.GenerateChangelogFromRcl(os.path.join(patches_folder, patch)))

        changelog = {"Changes" : defaultdict(int), "Additions" : defaultdict(int), "Deletions" : defaultdict(int)}
        for log in changelogs:
            for change_type in ["Changes", "Additions", "Deletions"]:
                for key, value in log[change_type].items():
                    changelog[change_type][key] = max(changelog[change_type][key], value)

        # Convert back to regular dict
        changelog = {k: dict(v) for k, v in changelog.items()}
        return changelog

    # Changelog from analyzing mod directory
    def GenerateChangelogFromMod(self, mod_path, checksum=False, verbose=False):
        info = GetInfoWithChecksum(mod_path + '/romfs', verbose) if checksum else GetInfo(mod_path + '/romfs', verbose)
        changelog = {"Changes" : {}, "Additions" : {}, "Deletions" : {}}
        if not self.hashmap:
            self._GenerateHashmap()
        strings = set(self.hashmap.values())
        with open(get_correct_path('restbl/ResourceSizeTable.Product.' + self.game_version + '.rsizetable.json'), 'r') as f:
            defaults = json.load(f, object_pairs_hook=lambda d: {int(k) if k.isdigit() else k: v for k, v in d})
        for file, file_info in info.items():
            if os.path.splitext(file)[1] not in ['.bwav', '.rsizetable'] and os.path.splitext(file)[0] != r"Pack\ZsDic":
                hash = binascii.crc32(file.encode()) if isinstance(file, str) else file
                add = True
                if checksum:
                    if os.path.splitext(file)[1] in ['.bgyml', '.ainb', '.bphhb', '.bphcl'] and file in defaults["Collision Table"] and file_info <= defaults["Collision Table"][file]:
                        add = False
                    elif os.path.splitext(file)[1] in ['.bgyml', '.ainb', '.bphhb', '.bphcl'] and hash in defaults["Hash Table"] and file_info <= defaults["Hash Table"][hash]:
                        add = False
                else:
                    if file in defaults["Collision Table"] and file_info == defaults["Collision Table"][file]:
                        add = False
                    elif hash in defaults["Hash Table"] and file_info == defaults["Hash Table"][hash]:
                        add = False
                if add:
                    if file in strings or file in self.collision_table:
                        changelog["Changes"][file] = file_info
                    else:
                        changelog["Additions"][file] = file_info
        changelog = dict(sorted(changelog.items()))
        return changelog
    
    # Same as above but for multiple mods
    def GenerateChangelogFromModDirectory(self, mod_path, delete=False, smart_analysis=True, checksum=False, verbose=False):
        changelogs = []
        mods = [mod for mod in os.listdir(mod_path) if os.path.isdir(os.path.join(mod_path, mod))]
        for mod in mods:
            suffix = '.Nin_NX_NVN' if self.game_version >= 140 else ''
            restbl_path = os.path.join(mod_path, mod, 'romfs/System/Resource/ResourceSizeTable.Product.' + self.game_version + suffix + '.rsizetable.zs')
            if smart_analysis:
                if os.path.exists(restbl_path):
                    print(f"Found RESTBL: {restbl_path}")
                    restbl = Restbl(restbl_path)
                    changelogs.append(restbl.GenerateChangelog())
                else:
                    print(f"Did not find RESTBL in {mod}")
                    changelogs.append(self.GenerateChangelogFromMod(os.path.join(mod_path, mod), checksum, verbose))
            else:
                changelogs.append(self.GenerateChangelogFromMod(os.path.join(mod_path, mod), checksum, verbose))
            if delete:
                try:
                    os.remove(restbl_path)
                    print(f"Removed {restbl_path}")
                except FileNotFoundError:
                    pass
        return MergeChangelogs(changelogs)
    
    # Loads the vanilla RESTBL values into the object
    @lru_cache(maxsize=None)
    def _load_json_file(self, filepath):
        with open(filepath, 'r') as f:
            return json.load(f, object_pairs_hook=lambda d: {int(k) if k.isdigit() else k: v for k, v in d})

    def LoadDefaults(self):
        data = self._load_json_file(get_correct_path('restbl/ResourceSizeTable.Product.' + self.game_version + '.rsizetable.json'))
        self.hash_table = data["Hash Table"]
        self.collision_table = data["Collision Table"]

    def clear_cache(self):
        self._load_json_file.cache_clear()

# List of all files in a directory
def GetStringList(romfs_path):
    paths = []
    zs = zstd.Zstd()
    for dir, subdir, files in os.walk(romfs_path):
        for file in files:
            full_path = os.path.join(dir, file)
            filepath = full_path
            if os.path.isfile(filepath):
                filepath = os.path.join(os.path.relpath(dir, romfs_path), os.path.basename(filepath))
                if os.path.splitext(filepath)[1] in ['.zs', '.zstd', '.mc']:
                    filepath = os.path.splitext(filepath)[0]
                if os.path.splitext(filepath)[1] not in ['.bwav', '.rsizetable', '.rcl'] and os.path.splitext(filepath)[0] != r"Pack\ZsDic":
                    filepath = filepath.replace('\\', '/')
                    paths.append(filepath)
                    print(filepath)
                    if os.path.splitext(filepath)[1] == '.pack':
                        try:
                            decompressed_data = zs.Decompress(full_path, no_output=True)
                            archive = sarc.Sarc(decompressed_data, filename=filepath)
                            paths += archive.ListFiles()
                        except Exception as e:
                            print(f"Failed to process file {filepath}: {str(e)}")
    paths = list(set(paths))
    paths.sort()
    return paths

# List of list of files for each mod in a directory
def GetFileLists(mod_path):
    mods = [mod for mod in os.listdir(mod_path) if os.path.isdir(os.path.join(mod_path, mod))]
    files = {}
    for mod in mods:
        if os.path.exists(os.path.join(mod_path, mod) + "/romfs"):
            files[mod] = GetStringList(os.path.join(mod_path, mod) + "/romfs")
    return files

# Same as above but stores the estimated entry size as well
def GetInfo(romfs_path, verbose=False):
    global version
    global game_file_extensions
    version_str = str(version)
    zs = zstd.Zstd()
    info = {}
    for dirpath, subdir, files in os.walk(romfs_path):
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext not in game_file_extensions:
                continue
            full_path = os.path.join(dirpath, file)
            filepath = full_path
            if os.path.isfile(filepath):
                filepath = os.path.join(os.path.relpath(dirpath, romfs_path), os.path.basename(filepath)).replace('\\', '/')
                # Check if the file is inside the RSDB folder and if it does not contain the version string
            if 'RSDB' in dirpath and file.endswith('.rstbl.byml.zs'):
                # Extract the version part of the filename
                file_version = file.split('.')[-4]  # Assuming the format is always like "Product.120.rstbl.byml"
                if file_version != version_str:
                    if verbose:
                        print(f"Ignoring {file} as its version {file_version} does not match the selected version {version_str}.")
                    continue  # Skip this file
            if os.path.splitext(filepath)[1] in ['.zs', '.zstd', '.mc'] and not file.endswith('.ta.zs'):
                filepath = os.path.splitext(filepath)[0]
            if os.path.splitext(filepath)[1] not in ['.bwav', '.rsizetable', '.rcl', '.webm'] and os.path.splitext(filepath)[0] != r"Pack\ZsDic":
                info[filepath] = CalcSize(full_path)
                if verbose:
                    print(filepath)
                if os.path.splitext(filepath)[1] == '.pack':
                    try:
                        decompressed_data = zs.Decompress(full_path, no_output=True)
                        archive = sarc.Sarc(decompressed_data, filename=filepath)
                        archive_info = archive.files
                        for f in archive_info:
                            try:
                                size = CalcSize(f["Name"], data=f["Data"])
                                if verbose:
                                    print(f["Name"])
                                if f["Name"] not in info:
                                    info[f["Name"]] = size
                                else:
                                    info[f["Name"]] = max(info[f["Name"]], size)
                            except Exception as e:
                                print(f"Failed to calculate size for {f['Name']} in {filepath}: {str(e)}")
                    except Exception as e:
                        print(f"Failed to process pack file {filepath}: {str(e)}")
    info = dict(sorted(info.items()))
    return info

checksums = None
index_cache = None

def get_checksum(path, filechecksum):
    global checksums, index_cache
    if checksums is None:
        checksums_file_path = "checksums/checksums.bin"
        checksums_file_path = get_correct_path(checksums_file_path)

        with open(checksums_file_path, "rb") as f:
            buffer = np.fromfile(f, dtype=np.uint64)

        half = len(buffer) // 2
        first_half = buffer[:half]
        second_half = buffer[half:]
        checksums = dict(zip(first_half, second_half))
        index_cache = {k: v for v, k in enumerate(first_half)}

    versions = ["140", "121", "120", "112", "111", "110", ""]
    for version in versions:
        key = xxhash.xxh64_intdigest((path + ('#' + version if version else '')).encode(encoding='UTF-16-LE', errors='strict'))
        if key in index_cache and checksums[key] == filechecksum:
            return np.uint64(1)

    # If no matching key is found, return 0
    return np.uint64(0)

# Same as GetInfo but does a checksum comparison first to see if the file has been modified
def GetInfoWithChecksum(romfs_path, verbose=False):
    global version
    global game_file_extensions
    version_str = str(version)
    info = {}
    zs = zstd.Zstd()
    for dir,subdir,files in os.walk(romfs_path):
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext not in game_file_extensions:
                continue
            full_path = os.path.join(dir, file)
            filepath = full_path
            if 'RSDB' in dir and file.endswith('.rstbl.byml.zs'):
                # Extract the version part of the filename
                file_version = file.split('.')[-4]  # Assuming the format is always like "Product.120.rstbl.byml"
                if file_version != version_str:
                    if verbose:
                        print(f"Ignoring {file} as its version {file_version} does not match the selected version {version_str}.")
                    continue  # Skip this file
            if os.path.isfile(filepath):
                filepath = os.path.join(os.path.relpath(dir, romfs_path), os.path.basename(filepath))
                filepath = filepath.replace('\\', '/')
                if os.path.splitext(filepath)[1] in ['.zs', '.zstd']:
                    data = zs.Decompress(full_path, no_output=True)
                    if data is None:
                        continue
                    checksum = xxhash.xxh64_intdigest(data)
                    stored_checksum = get_checksum(filepath, checksum)
                    if not file.endswith('.ta.zs'):
                        filepath = os.path.splitext(filepath)[0]
                elif os.path.splitext(filepath)[1] in ('.mc'):
                    with open(full_path, 'rb') as f:
                        data = f.read()
                    checksum = xxhash.xxh64_intdigest(data)
                    stored_checksum = get_checksum(filepath, checksum)
                    filepath = os.path.splitext(filepath)[0]
                else:
                    with open(full_path, 'rb') as f:
                        data = f.read()
                    checksum = xxhash.xxh64_intdigest(data)
                    stored_checksum = get_checksum(filepath, checksum)
                if os.path.splitext(filepath)[1] not in ['.bwav', '.rsizetable', '.rcl', '.webm'] and os.path.splitext(filepath)[0] != r"Pack\ZsDic":
                    if stored_checksum == 0:
                        add = True
                        if add:
                            info[filepath] = CalcSize(full_path)
                            if verbose:  # Only print if verbose is True
                                print(filepath)
                            if os.path.splitext(filepath)[1] == '.pack':
                                try:
                                    archive = sarc.Sarc(data, filename=filepath)
                                    archive_info = archive.files
                                    for f in archive_info:
                                        add = False
                                        full_path = full_path.replace("\\", "/")
                                        full_path = full_path.split("romfs/", 1)[-1]
                                        try:
                                            cs = xxhash.xxh64_intdigest(f["Data"])
                                            path_for_checksum = (full_path + "/" + f["Name"])
                                            stored_checksum = get_checksum(path_for_checksum, cs)
                                            if stored_checksum == 0:
                                                add = True
                                        except Exception as e:
                                            print(f"Failed to calculate checksum for {f['Name']} in {filepath}: {str(e)}")
                                            continue  # Skip this file but continue with others

                                        if add:
                                            try:
                                                size = CalcSize(f["Name"], data=f["Data"])
                                                if verbose:
                                                    print(f["Name"])
                                                if f["Name"] not in info:
                                                    info[f["Name"]] = size
                                                else:
                                                    info[f["Name"]] = max(info[f["Name"]], size)
                                            except Exception as e:
                                                print(f"Failed to calculate size for {f['Name']} in {filepath}: {str(e)}")
                                except Exception as e:
                                    print(f"Failed to process pack file {filepath}: {str(e)}")
    info = dict(sorted(info.items()))
    return info

# Same as above but for multiple mods
def GetInfoList(mod_path):
    mods = [mod for mod in os.listdir(mod_path) if os.path.isdir(os.path.join(mod_path, mod))]
    files = {}
    for mod in mods:
        files[mod] = GetInfo(os.path.join(mod_path, mod) + "/romfs")
    return files

# These are estimates, would be nice to have more precise values
def CalcSize(file, data=None):
    if data is None:
        with open(file, 'rb') as f:
            data = f.read()
    size = len(data)
    zs = zstd.Zstd()
    file_extension = os.path.splitext(file)[1]
    if file_extension in ['.zs', '.zstd'] and not file.endswith('.ta.zs'):
        size = zs.GetDecompressedSize(file)
        data = zs.Decompress(file, no_output=True)
        file = os.path.splitext(file)[0]
        file_extension = os.path.splitext(file)[1]
    if file_extension in ['.mc']:
        with open(file, 'rb') as reader:
            reader.read(4)
            reader.read(4)
            flags, = struct.unpack('<i', reader.read(4))
            decompressed_size = (flags >> 5) << (flags & 0xf)
            size = round(decompressed_size * 2) # This is an estimate of the entry for .bfres.mc
            file = os.path.splitext(file)[0]
            file_extension = os.path.splitext(file)[1]
    # Round up to the nearest 0x20 bytes
    size = ((size + 0x1F) // 0x20) * 0x20
    if file.endswith('.ta.zs'):
        size = size + 256
    if file_extension == '.bgyml':
        size = (size + 2000) * 8

    shader_archives = ['agl_resource.Nin_NX_NVN.release.sarc',
                        'gsys_resource.Nin_NX_NVN.release.sarc',
                        'tera_resource.Nin_NX_NVN.release.sarc',
                        'ApplicationPackage.Nin_NX_NVN.release.sarc']
    is_shader_archive = False
    for path in shader_archives:
        if path in os.path.abspath(file):
            is_shader_archive = True
            break
    if is_shader_archive:
        size += 3712
    
    # Add specific size differences for each file type
    size_diff_map = {
        '.ainb': 392,  # + exb allocations, handled separately below
        '.asb': 552,  # +40 per node, handled separately below
        '.baatarc': 256,
        '.baev': 288,
        '.bagst': 256,
        '.bars': 576,
        '.bcul': 256,
        '.beco': 256,
        '.belnk': 256,
        '.bfarc': 256,
        '.bfevfl': 288,  # one exception: Event/EventFlow/Dm_ED_0004.bfevfl is 480
        '.bfsha': 256,
        '.bgyml': 0,  # handled separately above
        '.bhtmp': 256,
        '.blal': 256,
        '.blarc': 256,
        '.blwp': 256,
        '.bnsh': 256,
        '.bntx': 256,
        '.bphcl': 256,
        '.bphhb': 256,
        '.bphnm': 288,
        '.bphsh': 368,
        '.bslnk': 256,
        '.bstar': 288,  # +8 per entry, handled separately below
        '.byml': 256,
        '.cai': 256,
        '.casset.byml': 448,
        '.chunk': 256,
        '.crbin': 256,
        '.cutinfo': 256,
        '.dpi': 256,
        '.genvb': 384,
        '.jpg': 256,
        '.mc': 0,  # handled separately above
        '.pack': 384,
        '.png': 256,
        '.quad': 256,
        '.sarc': 384,
        '.tscb': 256,
        '.txt': 256,
        '.txtg': 256,
        '.vsts': 256,
        '.wbr': 256,
        '.zs': 0  # handled separately, for .ta.zs files
    }
    
    if file_extension in size_diff_map:
        size += size_diff_map[file_extension]
    
        # Handle special cases
        if file_extension == '.asb':
            if data is None:
                with open(file, 'rb') as f:
                    f.seek(0x10)
                    node_count = int.from_bytes(f.read(4), byteorder='little')
                    f.seek(0x60)
                    offset = int.from_bytes(f.read(4), byteorder='little')
            else:
                node_count = int.from_bytes(data[0x10:0x14], byteorder='little')
                offset = int.from_bytes(data[0x60:0x64], byteorder='little')
            size += 40 * node_count
            has_exb = offset != 0
            if has_exb:
                if data is None:
                    with open(file, 'rb') as f:
                        f.seek(offset + 0x20)
                        new_offset = int.from_bytes(f.read(4), byteorder='little')
                        f.seek(new_offset + offset)
                        signature_count = int.from_bytes(f.read(4), byteorder='little')
                else:
                    new_offset = int.from_bytes(data[offset + 0x20:offset + 0x24], byteorder='little')
                    signature_count = int.from_bytes(data[new_offset + offset:new_offset + offset + 4], byteorder='little')
                size += 16 + ((signature_count + 1) // 2) * 8
        elif file_extension == '.bstar':
            if data is None:
                with open(file, 'rb') as f:
                    f.seek(0x08)
                    entry_count = int.from_bytes(f.read(4), byteorder='little')
            else:
                entry_count = int.from_bytes(data[0x08:0x0C], byteorder='little')
            size += 8 * entry_count
        elif file_extension == '.ainb':
            if data is None:
                with open(file, 'rb') as f:
                    f.seek(0x44)
                    offset = int.from_bytes(f.read(4), byteorder='little')
                    has_exb = offset != 0
                    if has_exb:
                        f.seek(offset + 0x20)
                        new_offset = int.from_bytes(f.read(4), byteorder='little')
                        f.seek(new_offset + offset)
                        signature_count = int.from_bytes(f.read(4), byteorder='little')
            else:
                offset = int.from_bytes(data[0x44:0x48], byteorder='little')
                has_exb = offset != 0
                if has_exb:
                    new_offset = int.from_bytes(data[offset + 0x20:offset + 0x24], byteorder='little')
                    signature_count = int.from_bytes(data[new_offset + offset:new_offset + offset + 4], byteorder='little')
            size += 16 + ((signature_count + 1) // 2) * 8

        if 'Event/EventFlow/Dm_ED_0004.bfevfl' in file:
            size += 192
        if 'static.Nin_NX_NVN.esetb.byml' in os.path.abspath(file):
            size += 3840
    else:
        size = (size + 1500) * 4
    if DEV_MODE:
        size = round(size * 1.3)
    return size

# Merges list of changelogs into one (doesn't accept RCL or YAML)
def MergeChangelogs(changelogs):
    changelog = {"Changes" : {}, "Additions" : {}, "Deletions" : {}}
    for log in changelogs:
        for change in log["Changes"]:
            if change not in changelog["Changes"]:
                changelog["Changes"][change] = log["Changes"][change]
            else:
                changelog["Changes"][change] = max(changelog["Changes"][change], log["Changes"][change])
        for addition in log["Additions"]:
            if addition not in changelog["Additions"]:
                changelog["Additions"][addition] = log["Additions"][addition]
            else:
                changelog["Additions"][addition] = max(changelog["Additions"][addition], log["Additions"][addition])
        for deletion in log["Deletions"]:
            if deletion not in changelog["Deletions"]:
                changelog["Deletions"][deletion] = log["Deletions"][deletion]
    changelog = dict(sorted(changelog.items()))
    return changelog

# Analyzes a directory of mods, generates a combined changelog, and generates a RESTBL from it
def MergeMods(mod_path, restbl_path='', version=140, compressed=True, delete=False, smart_analysis=True, checksum=False, verbose=False):
    try:
        start_time = time.time()
        directory = os.path.join(mod_path, "00_MERGED_RESTBL", "romfs", "System", "Resource")
        os.makedirs(directory, exist_ok=True)
        if not(os.path.exists(restbl_path)):
            print("Creating empty resource size table...")
            suffix = '.Nin_NX_NVN' if version >= 140 else ''
            filename = os.path.join(directory, 'ResourceSizeTable.Product.' + str(version).replace('.', '') + suffix + '.rsizetable')
            with open(filename, 'wb') as file:
                buffer = WriteStream(file)
                buffer.write("RESTBL".encode('utf-8'))
                buffer.write(u32(1))
                buffer.write(u32(0xA0))
                buffer.write(u32(0))
                buffer.write(u32(0))
            restbl = Restbl(filename)
            restbl.LoadDefaults()
        else:
            restbl = Restbl(restbl_path)
        print("Generating changelogs...")
        changelog = restbl.GenerateChangelogFromModDirectory(mod_path, delete, smart_analysis, checksum, verbose)
        with open('RestblChangelog.json', 'w') as f:
            json.dump(changelog, f, indent=4)
        print("Applying changes...")
        restbl.ApplyChangelog(changelog)
        restbl.Reserialize()
        if compressed:
            with open(restbl.filename, 'rb') as file:
                data = file.read()
            if os.path.exists(restbl.filename + '.zs'):
                os.remove(restbl.filename + '.zs')
            os.rename(restbl.filename, restbl.filename + '.zs')
            with open(restbl.filename + '.zs', 'wb') as file:
                compressor = zs.ZstdCompressor()
                file.write(compressor.compress(data))
        print("Finished")
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"All calculations were executed in {execution_time} seconds")
    finally:
        global index_cache, checksums
        index_cache = None
        checksums = None
        restbl.clear_cache()

# Gets the necessary filepaths and version info for MergeMods()
def merge_mods(mod_path=None, use_existing_restbl=False, restbl_path=None, version=None):
    if not mod_path:
        mod_path = input("Enter the directory containing mods to merge: ")
    if use_existing_restbl and not restbl_path:
        restbl_path = input("Enter the path to the existing RESTBL file: ")
    if not version:
        version = input("Enter the version: ")
    if not restbl_path:
        restbl_path = ''  # Set restbl_path to an empty string if it's not provided
    return mod_path, restbl_path, version

# Generates changelogs for the two RESTBL files to merge
def merge_restbl(restbl_path0, restbl_path1):
    restbl0 = Restbl(restbl_path0)
    restbl1 = Restbl(restbl_path1)
    return restbl0.GenerateChangelog(), restbl1.GenerateChangelog(), restbl0

# Generates a changelog in the specified format
def gen_changelog(restbl_path, format):
    restbl = Restbl(restbl_path)
    print("Generating changelog...")
    if format == 'json':
        changelog = restbl.GenerateChangelog()
        with open('changelog.json', 'w') as f:
            json.dump(changelog, f, indent=4)
    elif format == 'rcl':
        restbl.GenerateRcl()
    elif format == 'yaml':
        restbl.GenerateYamlPatch()
    else:
        raise ValueError("Invalid format. Choose between 'json', 'rcl', or 'yaml'.")
    print("Finished")

# Applies all RCL/YAML patches in a patch folder
def apply_patches(patch_restbl, patches_path, compressed=True):
    restbl = Restbl(patch_restbl)
    print("Analyzing patches...")
    patches = [i for i in os.listdir(patches_path) if os.path.isfile(os.path.join(patches_path, i)) and os.path.splitext(i)[1].lower() in ['.json', '.yml', '.yaml', '.rcl']]
    print("Found patches:", patches)  # Add this line for debug information
    changelogs = []
    for patch in patches:
        match os.path.splitext(patch)[1].lower():
            case '.json':
                with open(os.path.join(patches_path, patch), 'r') as f:
                    changelogs.append(json.load(f, object_pairs_hook=lambda d: {int(k) if k.isdigit() else k: v for k, v in d}))
            case '.yml' | '.yaml':
                changelogs.append(restbl.GenerateChangelogFromYaml(os.path.join(patches_path, patch)))
            case '.rcl':
                changelogs.append(restbl.GenerateChangelogFromRcl(os.path.join(patches_path, patch)))
    print("Merging patches...")
    changelog = MergeChangelogs(changelogs)
    print("Applying patches...")
    restbl.ApplyChangelog(changelog)
    restbl.Reserialize()
    if compressed:
        with open(restbl.filename, 'rb') as file:
            data = file.read()
        if os.path.exists(restbl.filename + '.zs'):
            os.remove(restbl.filename + '.zs')
        os.rename(restbl.filename, restbl.filename + '.zs')
        with open(restbl.filename + '.zs', 'wb') as file:
            compressor = zs.ZstdCompressor()
            file.write(compressor.compress(data))
    print("Finished")

def GenerateRestblFromSingleMod(mod_path, restbl_path='', version=140, compressed=True, checksum=False, verbose=False):
    try:
        start_time = time.time()
        if not(os.path.exists(restbl_path)):
            print("Creating empty resource size table...")
            directory = os.path.join(mod_path, "romfs", "System", "Resource")
            os.makedirs(directory, exist_ok=True)
            suffix = '.Nin_NX_NVN' if version >= 140 else ''
            filename = os.path.join(directory, 'ResourceSizeTable.Product.' + str(version).replace('.', '') + suffix + '.rsizetable')
            filename = filename.replace("/", "\\")
            with open(filename, 'wb') as file:
                buffer = WriteStream(file)
                buffer.write("RESTBL".encode('utf-8'))
                buffer.write(u32(1))
                buffer.write(u32(0xA0))
                buffer.write(u32(0))
                buffer.write(u32(0))
            restbl = Restbl(filename)
            restbl.LoadDefaults()
        else:
            restbl = Restbl(restbl_path)
        print("Generating changelog...")
        changelog = restbl.GenerateChangelogFromMod(mod_path, checksum, verbose)
        with open('RestblChangelog.json', 'w') as f:
            json.dump(changelog, f, indent=4)
        print("Applying changes...")
        restbl.ApplyChangelog(changelog)
        restbl.Reserialize()
        if compressed:
            with open(restbl.filename, 'rb') as file:
                data = file.read()
            if os.path.exists(restbl.filename + '.zs'):
                os.remove(restbl.filename + '.zs')
            os.rename(restbl.filename, restbl.filename + '.zs')
            with open(restbl.filename + '.zs', 'wb') as file:
                compressor = zs.ZstdCompressor()
                file.write(compressor.compress(data))
            filename = filename + ".zs"
        print("Finished")
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"All calculations were executed in {execution_time} seconds")
        print("RESTBL saved at:", filename)
    finally:
        global index_cache, checksums
        index_cache = None
        checksums = None
        restbl.clear_cache()

def open_tool():
    # GUI version
    print(welcome())
    import PySimpleGUI as sg
    global DEV_MODE
    global version
    sg.theme('Black')
    version_map = {
        '1.0.0': 100,
        '1.1.0': 110,
        '1.1.1': 111,
        '1.1.2': 112,
        '1.2.0': 120,
        '1.2.1': 121,
        '1.4.0': 140,
    }
    layout = [
        [
            sg.Column([
                [sg.Column([
                    [sg.Text('Options:'), 
                    sg.Checkbox(default=True, text='Compress', size=(8,5), key='compressed'),
                    sg.Checkbox(default=False, text='Use Existing RESTBL', size=(17,5), key='smart_analyze'),
                    sg.Checkbox(default=False, text='Delete Existing RESTBL', size=(19,5), key='delete')],
                    [sg.Text(' ', size=(6, 1)),  # Empty text element to create offset
                    sg.Checkbox(default=True, text='Use Checksums', size=(12,5), key='use_checksums'),
                    sg.Checkbox(default=False, text='Verbose', size=(8,5), key='verbose'),
                    sg.Text('Version:'), sg.Combo(list(version_map.keys()), default_value='1.4.0', key='version', readonly=True)],
                    [sg.Text(' ', size=(6, 1)),  # Empty text element to create offset
                    sg.Checkbox(default=False, text='Patch existing RESTBL', key='patch_existing', size=(20, 1)),
                    sg.Checkbox('Dev Mode', default=False, key='dev_mode')]
                ], size=(510, 90))],
                [sg.Frame('Calculate RESTBL from Multiple Mods', [
                    [sg.Column([
                        [sg.Text('Mod Path:', size=(14, 1)), sg.Input(key='mod_path', size=(44, 1)), sg.FolderBrowse()],
                        [sg.Text('', size=(1, 1)),
                        sg.Button('Calculate RESTBL', size=(14, 1)),
                        sg.Text('', size=(1, 1))
                        ]
                    ], size=(510, 70), element_justification='center')]
                ])],
                [sg.Frame('Calculate RESTBL from Single Mod', [
                    [sg.Column([
                        [sg.Text('Mod Path:', size=(14, 1)), sg.Input(key='single_mod_path', size=(44, 1)), sg.FolderBrowse()],
                        [sg.Text('', size=(1, 1)),
                        sg.Button('Calculate (single mod)', size=(20, 1)),
                        sg.Text('', size=(1, 1))
                        ]
                    ], size=(510, 70), element_justification='center')]
                ])],
                [sg.Frame('Merge RESTBLs', [
                    [sg.Column([
                        [sg.Text('RESTBL Path 1:', size=(14, 1)), sg.Input(key='restbl_path0', size=(44, 1)), sg.FileBrowse(file_types=(("RESTBL Files", "*.rsizetable*"),))],
                        [sg.Text('RESTBL Path 2:', size=(14, 1)), sg.Input(key='restbl_path1', size=(44, 1)), sg.FileBrowse(file_types=(("RESTBL Files", "*.rsizetable*"),))],
                        [sg.Text('', size=(1, 1)),
                        sg.Button('Merge RESTBLs', size=(14, 1)),
                        sg.Text('', size=(1, 1))
                        ]
                    ], size=(510, 95), element_justification='center')]
                ])],
                [sg.Frame('Generate Changelog', [
                    [sg.Column([
                        [sg.Text('RESTBL Path:', size=(14, 1)), sg.Input(key='log_restbl_path', size=(44, 1)), sg.FileBrowse(file_types=(("RESTBL Files", "*.rsizetable*"),))],
                        [sg.Text('Format:', size=(14, 1)), sg.Combo(['json', 'rcl', 'yaml'], default_value='json', key='format')],
                        [sg.Text('', size=(1, 1)),
                        sg.Button('Generate Changelog', size=(16, 1)),
                        sg.Text('', size=(1, 1))
                        ]
                    ], size=(510, 90), element_justification='center')]
                ])],
                [sg.Frame('Apply Patches', [
                    [sg.Column([
                        [sg.Text('RESTBL to patch:', size=(14, 1)), sg.Input(key='patch_restbl', size=(44, 1)), sg.FileBrowse(file_types=(("RESTBL Files", "*.rsizetable*"),))],
                        [sg.Text('Folder with patches:', size=(14, 1)), sg.Input(key='patches_path', size=(44, 1)), sg.FolderBrowse()],
                        [sg.Text('', size=(1, 1)),
                        sg.Button('Apply Patches', size=(14, 1)),
                        sg.Text('', size=(1, 1))
                        ]
                    ], size=(510, 97), element_justification='center')]
                ])],
                [sg.Button('Exit')]
            ])
        ]
    ]
    window = sg.Window('RESTBL Calculator 1.5.0', icon=images).Layout(layout)
    while True:
        event, values = window.read()
        if event == sg.WINDOW_CLOSED or event == 'Exit':
            break

        if values['patch_existing']:
            restbl_to_patch = sg.PopupGetFile('Please select a RESTBL file to patch with the new calculated values', file_types=(("RESTBL Files", "*.rsizetable*"),), title='Select RESTBL File')
            if not restbl_to_patch:
                sg.Popup('Please select a RESTBL file.')
                continue
        else:
            restbl_to_patch = ''

        if event == 'Calculate RESTBL':
            import gc
            import threading
            mod_path = values['mod_path']
            DEV_MODE = values['dev_mode']
            if not os.path.isdir(mod_path):
                sg.Popup('Please enter a correct mod folder path.', title='Error')
            else:
                version = version_map[values['version']]
                popup = sg.Window('Please wait...', [[sg.Text('Please wait...')]], auto_close=False, disable_close=True, finalize=True)
                thread = threading.Thread(target=MergeMods, args=(mod_path, restbl_to_patch, version, values['compressed'], values['delete'], values['smart_analyze'], values['use_checksums'], values['verbose']))
                thread.start()
                while True:
                    # Process events and update the screen
                    event, values = window.read(timeout=1000)  # Add a small delay
                    # Check if the thread is still running
                    if not thread.is_alive():
                        popup.close()
                        sg.Popup('Action completed!')
                        break
                gc.collect()

        elif event == 'Merge RESTBLs':
            restbl_path0 = values['restbl_path0']
            restbl_path1 = values['restbl_path1']
            if not (os.path.isfile(restbl_path0) and os.path.isfile(restbl_path1) and 
                    (restbl_path0.endswith(('.rsizetable', '.rsizetable.zs')) and 
                    restbl_path1.endswith(('.rsizetable', '.rsizetable.zs')))):
                sg.Popup('Please select two resource tables to merge', title='Error')
            else:
                popup = sg.Window('Please wait...', [[sg.Text('Please wait...')]], auto_close=False, disable_close=True, finalize=True)
                window.read(timeout=0)
                popup.bring_to_front()
                changelog0, changelog1, restbl = merge_restbl(restbl_path0, restbl_path1)
                filename = os.path.basename(restbl.filename)
                restbl.filename = os.path.join(os.getcwd(), filename)
                print(restbl.filename)
                print("Calculating merged changelog...")
                changelog = MergeChangelogs([changelog0, changelog1])
                print("Applying changes...")
                restbl.ApplyChangelog(changelog)
                restbl.Reserialize()
                if values['compressed']:
                    with open(restbl.filename, 'rb') as file:
                        data = file.read()
                    if os.path.exists(restbl.filename + '.zs'):
                        os.remove(restbl.filename + '.zs')
                    os.rename(restbl.filename, restbl.filename + '.zs')
                    with open(restbl.filename + '.zs', 'wb') as file:
                        compressor = zs.ZstdCompressor()
                        file.write(compressor.compress(data))
                print("Finished")
                popup.close()
                sg.Popup('Action completed!')

        elif event == 'Generate Changelog':
            log_restbl_path = values['log_restbl_path']
            if not (os.path.isfile(log_restbl_path) and 
                    (log_restbl_path.endswith(('.rsizetable', '.rsizetable.zs')))):
                sg.Popup('Please select a resource table to generate a changelog', title='Error')
            else:
                popup = sg.Window('Please wait...', [[sg.Text('Please wait...')]], auto_close=False, disable_close=True, finalize=True)
                window.read(timeout=0)
                popup.bring_to_front()
                gen_changelog(values['log_restbl_path'], values['format'])
                popup.close()
                sg.Popup('Action completed!')

        elif event == 'Apply Patches':
            patch_restbl = values['patch_restbl']
            patches_path = values['patches_path']
            if not (os.path.isfile(patch_restbl) and os.path.isdir(patches_path) and 
                    (patch_restbl.endswith(('.rsizetable', '.rsizetable.zs')))):
                sg.Popup('Please select a resource table to patch and a folder containing patches.', title='Error')
            else:
                popup = sg.Window('Please wait...', [[sg.Text('Please wait...')]], auto_close=False, disable_close=True, finalize=True)
                window.read(timeout=0)
                popup.bring_to_front()
                apply_patches(values['patch_restbl'], values['patches_path'], compressed=values['compressed'])
                print("Finished")
                popup.close()
                sg.Popup('Action completed!')

        elif event == 'Calculate (single mod)':
            import gc
            import threading
            DEV_MODE = values['dev_mode']
            mod_path = values['single_mod_path']
            if not os.path.isdir(mod_path):
                sg.Popup('Please enter a correct mod folder path.', title='Error')
            else:
                version = version_map[values['version']]
                popup = sg.Window('Please wait...', [[sg.Text('Please wait...')]], auto_close=False, disable_close=True, finalize=True)
                thread = threading.Thread(target=GenerateRestblFromSingleMod, args=(mod_path, restbl_to_patch, version, values['compressed'], values['use_checksums'], values['verbose']))
                thread.start()
                while True:
                    event, values = window.read(timeout=1000)
                    if not thread.is_alive():
                        popup.close()
                        sg.Popup('Action completed!')
                        break
                gc.collect()
    window.close()
            
if __name__ == "__main__":
    # Check if any command-line arguments were passed
    if len(sys.argv) > 1:
        print(welcome())
        parser = argparse.ArgumentParser(description='RESTBL Tool', formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-a', '--action', choices=['merge-mods', 'merge-restbl', 'generate-changelog', 'apply-patches', 'single-mod'], required=True, help='Action to perform')
        parser.add_argument('-c', '--compress', action='store_true', help='Compress the output')
        parser.add_argument('-v', '--verbose', action='store_true', help='Print the list of edited files from mods')
        parser.add_argument('-dev', '--dev-mode', action='store_true', help='Multiply the calculated sizes by a factor of 1.2 for testing')
        parser.add_argument('-cs', '--use-checksums', action='store_true', help='[Recommended] Use checksums')
        parser.add_argument('-m', '--mod-path', type=str, help='Mandatory for actions "merge-mods" and "single-mod"')
        parser.add_argument('-r', '--restbl-path', type=str, help='(Optional) Path to a RESTBL file to patch when calculating entries for mods')
        parser.add_argument('-ver', '--version', type=int, default=140, help='(Optional) TotK version - default: 140')

        # Arguments for 'merge-mods' action
        merge_mods_group = parser.add_argument_group('merge-mods')
        merge_mods_group.add_argument('-u', '--use-existing-restbl', action='store_true', help='(Optional) Use existing RESTBL')
        merge_mods_group.add_argument('-d', '--delete-existing-restbl', action='store_true', help='(Optional) Delete existing RESTBL')

        # Arguments for 'merge-restbl' action
        merge_restbl_group = parser.add_argument_group('merge-restbl')
        merge_restbl_group.add_argument('-r0', '--restbl-path0', type=str, help='(Mandatory) Path to the first RESTBL file to merge')
        merge_restbl_group.add_argument('-r1', '--restbl-path1', type=str, help='(Mandatory) Path to the second RESTBL file to merge')

        # Arguments for 'generate-changelog' action
        gen_changelog_group = parser.add_argument_group('generate-changelog')
        gen_changelog_group.add_argument('-l', '--log-restbl-path', type=str, help='(Mandatory) Path to the RESTBL file for generating changelog')
        gen_changelog_group.add_argument('-f', '--format', choices=['json', 'rcl', 'yaml'], help='(Mandatory) Format of the changelog')

        # Arguments for 'apply-patches' action
        apply_patches_group = parser.add_argument_group('apply-patches')
        apply_patches_group.add_argument('-p', '--patch-restbl', type=str, help='(Mandatory) Path to the RESTBL file to patch')
        apply_patches_group.add_argument('-pp', '--patches-path', type=str, help='(Mandatory) Path to the folder containing patches (rcl, yaml, json)')

        args = parser.parse_args()
        DEV_MODE = args.dev_mode
        version = args.version

        if args.action == 'merge-mods':
            if args.restbl_path is None:
                restbl_path = ''  # Set restbl_path to an empty string if it's not provided
            else:
                restbl_path = args.restbl_path
            MergeMods(args.mod_path, restbl_path, version, args.compress, args.delete_existing_restbl, args.use_existing_restbl, args.use_checksums, args.verbose)
        elif args.action == 'merge-restbl':
            # Replace the file browsing dialog with command line arguments
            restbl_path0 = args.restbl_path0
            restbl_path1 = args.restbl_path1
            restbl0 = Restbl(restbl_path0)
            restbl1 = Restbl(restbl_path1)
            changelog0, changelog1, restbl = restbl0.GenerateChangelog(), restbl1.GenerateChangelog(), restbl0
            print("Calculating merged changelog...")
            changelog = MergeChangelogs([changelog0, changelog1])
            print("Applying changes...")
            restbl.ApplyChangelog(changelog)
            restbl.Reserialize()
            if args.compress:
                with open(restbl.filename, 'rb') as file:
                    data = file.read()
                if os.path.exists(restbl.filename + '.zs'):
                    os.remove(restbl.filename + '.zs')
                os.rename(restbl.filename, restbl.filename + '.zs')
                with open(restbl.filename + '.zs', 'wb') as file:
                    compressor = zs.ZstdCompressor()
                    file.write(compressor.compress(data))
            print("Finished")
        elif args.action == 'generate-changelog':
            gen_changelog(args.log_restbl_path, args.format)
        elif args.action == 'apply-patches':
            apply_patches(args.patch_restbl, args.patches_path, compressed=args.compress)
        elif args.action == 'single-mod':
            if args.restbl_path is None:
                restbl_path = ''  # Set restbl_path to an empty string if it's not provided
            else:
                restbl_path = args.restbl_path
            GenerateRestblFromSingleMod(args.mod_path, restbl_path, version, args.compress, args.use_checksums, args.verbose)
    else:
        # No command-line arguments were passed
        open_tool()

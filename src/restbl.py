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
import time
import zstd
import subprocess
import shutil

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

    def ConvertToJson(self, output_path=''):
        if not output_path:
            output_path = os.path.splitext(self.filename)[0] + '.json'
            
        json_data = {
            "Hash Table": self.hash_table,
            "Collision Table": self.collision_table
        }
        
        with open(output_path, 'w') as f:
            json.dump(json_data, f, indent=4)
            
        print(f"Converted RESTBL to JSON: {output_path}")

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

    versions = ["141", "140", "121", "120", "112", "111", "110", ""]
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
def MergeMods(mod_path, restbl_path='', version=141, compressed=True, delete=False, smart_analysis=True, checksum=False, verbose=False, dev_mode=False):
    try:
        global DEV_MODE
        DEV_MODE = dev_mode
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

def GenerateRestblFromSingleMod(mod_path, restbl_path='', version=141, compressed=True, checksum=False, verbose=False, dev_mode=False):
    try:
        global DEV_MODE
        DEV_MODE = dev_mode
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

def UpdateRestblTool():
    version_map = {
        '1.0.0',
        '1.1.0',
        '1.1.1',
        '1.1.2',
        '1.2.0',
        '1.2.1',
        '1.4.0',
        '1.4.1'
    }
    
    # Convert RESTBL to JSON
    totk_path = "F:\\TOTK"
    latest_version = sorted(list(version_map))[-1]
    latest_version_without_dots = latest_version.replace('.', '')
    romfs_path = os.path.join(totk_path, latest_version)
    restbl_path = os.path.join(romfs_path, "System", "Resource", "ResourceSizeTable.Product." + latest_version_without_dots + ".Nin_NX_NVN.rsizetable.zs")
    restbl = Restbl(restbl_path)
    restbl.ConvertToJson(r"F:\dev\restbl-master\restbl\ResourceSizeTable.Product.{}.rsizetable.json".format(latest_version_without_dots))
    
    # Run HashCalculator
    hash_calculator_path = r"F:\dev\Totk.HashCalculator\src\bin\Release\net7.0\Totk.HashCalculator.exe"
    temp_output_dir = r"F:\dev\restbl-master\string_lists\temp"
    final_output_dir = r"F:\dev\restbl-master\string_lists"
    
    try:
        subprocess.run([
            hash_calculator_path,
            romfs_path,
            "-v", latest_version,
            "-o", temp_output_dir
        ], check=True)
        
        temp_file = os.path.join(temp_output_dir, f"string-table-{latest_version}.txt")
        final_file = os.path.join(final_output_dir, f"{latest_version_without_dots}.txt")
        
        os.makedirs(final_output_dir, exist_ok=True)
        if os.path.exists(final_file):
            os.remove(final_file)
        os.rename(temp_file, final_file)
        shutil.rmtree(temp_output_dir)
        print("\n\n")

    except Exception as e:
        print(f"\n\nError during HashCalculator process: {str(e)}")

    # Run ChecksumGenerator for all versions
    checksum_generator_path = r"F:\dev\ModuleSystem.ChecksumGenerator\src\bin\release\net8.0\ModuleSystem.ChecksumGenerator.exe"
    checksum_output_path = r"F:\dev\restbl-master\checksums\checksums.bin"
    version_paths = "|".join([f"F:\\TOTK\\{version}" for version in sorted(version_map)])
    
    try:
        subprocess.run([
            checksum_generator_path,
            version_paths,
            "-o", checksum_output_path
        ], check=True)
        print("\n\nSuccessfully generated checksums for all versions")
    except Exception as e:
        print(f"\n\nError during ChecksumGenerator process: {str(e)}")

UpdateRestblTool()
from utils import *
try:
    import zstandard as zs
    import yaml
except ImportError:
    raise ImportError("Would you be so kind as to LEARN TO FUCKING READ INSTRUCTIONS")
from collections import defaultdict
from functools import lru_cache
import numpy as np
import xxhash
import sarc
import os
import binascii
import json
import sys

# For pyinstaller relative paths
def get_correct_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def get_app_data_path():
    if os.name == 'nt':  # Windows
        return os.environ.get('LOCALAPPDATA')
    else:  # Linux and macOS
        return os.path.join(os.path.expanduser('~'), '.local', 'share')

app_data_path = get_app_data_path()
config_path = os.path.join(app_data_path, 'TotK')
config_json_path = os.path.join(config_path, 'config.json')
checksum_bin = os.path.join(config_path, 'checksums.bin')
os.makedirs(config_path, exist_ok=True)

def check_config():
    # Check if config.json exists
    if not os.path.exists(config_json_path):
        # Prompt the user for the RomFS Dump Path
        game_path = input("Please enter the RomFS Dump Path: ")

        # Create the config.json file
        with open(config_json_path, 'w') as f:
            json.dump({"GamePath": game_path}, f)
    else:
        # Load the config.json file
        with open(config_json_path, 'r') as f:
            config = json.load(f)

        # Check for the existence of Pack\ZsDic.pack.zs
        game_path = config["GamePath"]
        zs_dic_path = os.path.join(game_path, 'Pack', 'ZsDic.pack.zs')
        if not os.path.exists(zs_dic_path):
            print("Invalid game dump, missing ZsDic.pack.zs")
            sys.exit()

    # If checksums.bin doesn't exist, download it
    if not os.path.exists(checksum_bin):
        import requests
        url = "https://github.com/MasterBubbles/restbl-cli/raw/master/checksums.bin"
        print("Checksums are missing, downloading them from: " + url)
        response = requests.get(url)
        with open(checksum_bin, 'wb') as f:
            f.write(response.content)

check_config()
import zstd

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
        self.filename = os.path.basename(filepath)
        self.game_version = os.path.splitext(os.path.splitext(filepath)[0])[1][1:]
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
            version = os.path.splitext(os.path.splitext(os.path.basename(self.filename))[0])[1]
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
    def GenerateChangelogFromMod(self, mod_path, checksum=False):
        info = GetInfoWithChecksum(mod_path + '/romfs', self.game_version) if checksum else GetInfo(mod_path + '/romfs')
        changelog = {"Changes" : {}, "Additions" : {}, "Deletions" : {}}
        if not self.hashmap:
            self._GenerateHashmap()
        strings = set(self.hashmap.values())
        with open(get_correct_path('restbl/ResourceSizeTable.Product.' + self.game_version + '.rsizetable.json'), 'r') as f:
            defaults = json.load(f, object_pairs_hook=lambda d: {int(k) if k.isdigit() else k: v for k, v in d})
        for file, file_info in info.items():
            if os.path.splitext(file)[1] not in ['.bwav', '.rsizetable'] and os.path.splitext(file)[0] != r"Pack\ZsDic":
                hash = binascii.crc32(file.encode()) if isinstance(file, str) else file
                add = False
                if checksum:
                    # Only overwrite if the entry is larger than the original entry
                    # This is mostly in case the mod contains multiple copies of a file in a pack of differing sizes
                    if file in defaults["Collision Table"] and file_info > defaults["Collision Table"][file]:
                        add = True
                    elif hash in defaults["Hash Table"] and file_info > defaults["Hash Table"][hash]:
                        add = True
                    else:
                        add = True
                else:
                    add = True
                if add:
                    if file in strings or file in self.collision_table:
                        changelog["Changes"][file] = file_info
                    else:
                        changelog["Additions"][file] = file_info
        changelog = dict(sorted(changelog.items()))
        return changelog
    
    # Same as above but for multiple mods
    def GenerateChangelogFromModDirectory(self, mod_path, delete=False, smart_analysis=True, checksum=False):
        changelogs = []
        mods = [mod for mod in os.listdir(mod_path) if os.path.isdir(os.path.join(mod_path, mod))]
        for mod in mods:
            restbl_path = os.path.join(mod_path, mod, 'romfs/System/Resource/ResourceSizeTable.Product.' + self.game_version + '.rsizetable.zs')
            if smart_analysis:
                if os.path.exists(restbl_path):
                    print(f"Found RESTBL: {restbl_path}")
                    restbl = Restbl(restbl_path)
                    changelogs.append(restbl.GenerateChangelog())
                else:
                    print(f"Did not find RESTBL in {mod}")
                    changelogs.append(self.GenerateChangelogFromMod(os.path.join(mod_path, mod), checksum))
            else:
                changelogs.append(self.GenerateChangelogFromMod(os.path.join(mod_path, mod), checksum))
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

# List of all files in a directory
def GetStringList(romfs_path):
    paths = []
    zs = zstd.Zstd()
    for dir,subdir,files in os.walk(romfs_path):
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
                        archive = sarc.Sarc(zs.Decompress(full_path, no_output=True))
                        paths += archive.ListFiles()
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
def GetInfo(romfs_path):
    info = {}
    zs = zstd.Zstd()
    for dir,subdir,files in os.walk(romfs_path):
        for file in files:
            full_path = os.path.join(dir, file)
            filepath = full_path
            if os.path.isfile(filepath):
                filepath = os.path.join(os.path.relpath(dir, romfs_path), os.path.basename(filepath))
                if os.path.splitext(filepath)[1] in ['.zs', '.zstd', '.mc']:
                    filepath = os.path.splitext(filepath)[0]
                if os.path.splitext(filepath)[1] not in ['.bwav', '.rsizetable', '.rcl'] and os.path.splitext(filepath)[0] != r"Pack\ZsDic":
                    filepath = filepath.replace('\\', '/')
                    info[filepath] = CalcSize(full_path)
                    print(filepath)
                    if os.path.splitext(filepath)[1] == '.pack':
                        archive = sarc.Sarc(zs.Decompress(full_path, no_output=True))
                        archive_info = archive.ListFileInfo()
                        for f in archive_info:
                            size = CalcSize(f, archive_info[f])
                            if f not in info:
                                info[f] = size
                            else:
                                info[f] = max(info[f], size)
    info = dict(sorted(info.items()))
    return info

checksums = None
index_cache = None

def get_checksum(path, filechecksum):
    global checksums, index_cache
    if checksums is None:
        app_data_path = get_app_data_path()
        checksums_file_path = os.path.join(app_data_path, 'TotK', 'checksums.bin')

        with open(checksums_file_path, "rb") as f:
            buffer = np.fromfile(f, dtype=np.uint64)

        half = len(buffer) // 2
        first_half = buffer[:half]
        second_half = buffer[half:]
        checksums = dict(zip(first_half, second_half))
        index_cache = {k: v for v, k in enumerate(first_half)}

    versions = ["121", "120", "112", "111", "110", ""]
    for version in versions:
        key = xxhash.xxh64_intdigest((path + ('#' + version if version else '')).encode(encoding='UTF-16-LE', errors='strict'))
        if key in index_cache and checksums[key] == filechecksum:
            return np.uint64(1)

    # If no matching key is found, return 0
    return np.uint64(0)

# Same as GetInfo but does a checksum comparison first to see if the file has been modified
def GetInfoWithChecksum(romfs_path, version=121):
    info = {}
    zs = zstd.Zstd()
    for dir,subdir,files in os.walk(romfs_path):
        for file in files:
            full_path = os.path.join(dir, file)
            filepath = full_path
            with open(full_path, 'rb') as f:
                data = f.read()
            checksum = xxhash.xxh64_intdigest(data)
            if os.path.isfile(filepath):
                filepath = os.path.join(os.path.relpath(dir, romfs_path), os.path.basename(filepath))
                if os.path.splitext(filepath)[1] in ['.zs', '.zstd', '.mc']:
                    filepath = os.path.splitext(filepath)[0]
                if os.path.splitext(filepath)[1] not in ['.bwav', '.rsizetable', '.rcl'] and os.path.splitext(filepath)[0] != r"Pack\ZsDic":
                    filepath = filepath.replace('\\', '/')
                    add = False
                    stored_checksum = get_checksum(filepath, checksum)
                    if stored_checksum == 0:
                        add = True
                    if add:
                        info[filepath] = CalcSize(full_path)
                        #print(filepath)
                        if os.path.splitext(filepath)[1] == '.pack':
                            archive = sarc.Sarc(zs.Decompress(full_path, no_output=True))
                            archive_info = archive.files
                            for f in archive_info:
                                full_path = full_path.replace("\\", "/")
                                full_path = full_path.split("romfs/", 1)[-1]
                                cs = xxhash.xxh64_intdigest(f["Data"])
                                add = False
                                path_for_checksum = (full_path + "/" + f["Name"])
                                stored_checksum = get_checksum(path_for_checksum, cs)
                                if stored_checksum == 0:
                                    add = True
                                if add:
                                    size = CalcSize(f["Name"], len(f["Data"]))
                                    #print (f["Name"])
                                    if f["Name"] not in info:
                                        info[f["Name"]] = size
                                    else:
                                        info[f["Name"]] = max(info[f["Name"]], size)
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
def CalcSize(file, size=None):
    if size == None:
        size = os.path.getsize(file)
    zs = zstd.Zstd()
    if os.path.splitext(file)[1] in ['.zs', '.zstd']:
        size = zs.GetDecompressedSize(file)
        file = os.path.splitext(file)[0]
    elif os.path.splitext(file)[1] in ['.mc']:
        size = os.path.getsize(file) * 5 # MC decompressor wasn't working so this is an estimate of the decompressed size
        file = os.path.splitext(file)[0]
    if os.path.splitext(file)[1] == '.txtg':
        return size + 5000
    elif os.path.splitext(file)[1] == '.bgyml':
        return (size + 1000) * 8
    else:
        return (size + 1500) * 4

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
def MergeMods(mod_path, restbl_path='', version=121, compressed=True, delete=False, smart_analysis=True, checksum=False):
    if not(os.path.exists(restbl_path)):
        print("Creating empty resource size table...")
        filename = os.path.join(restbl_path, 'ResourceSizeTable.Product.' + str(version).replace('.', '') + '.rsizetable')
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
    changelog = restbl.GenerateChangelogFromModDirectory(mod_path, delete, smart_analysis, checksum)
    with open('test.json', 'w') as f:
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

import argparse

def open_tool():
    parser = argparse.ArgumentParser(description='RESTBL Tool', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--action', choices=['merge-mods', 'merge-restbl', 'generate-changelog', 'apply-patches'], required=True, help='Action to perform')
    parser.add_argument('--compress', action='store_true', help='Compress the output')

    # Arguments for 'merge-mods' action
    merge_mods_group = parser.add_argument_group('merge-mods')
    merge_mods_group.add_argument('--mod-path', type=str, help='(Mandatory) Path to the mod directory')
    merge_mods_group.add_argument('--version', type=int, default=121, help='(Optional) TotK version - default: 121')
    merge_mods_group.add_argument('--use-existing-restbl', action='store_true', help='(Optional) Use existing RESTBL')
    merge_mods_group.add_argument('--restbl-path', type=str, help='(Optional) Path to the RESTBL file to use')
    merge_mods_group.add_argument('--delete-existing-restbl', action='store_true', help='(Optional) Delete existing RESTBL')
    merge_mods_group.add_argument('--use-checksums', action='store_true', help='(Optional) Use checksums')

    # Arguments for 'merge-restbl' action
    merge_restbl_group = parser.add_argument_group('merge-restbl')
    merge_restbl_group.add_argument('--restbl-path0', type=str, help='(Mandatory) Path to the first RESTBL file to merge')
    merge_restbl_group.add_argument('--restbl-path1', type=str, help='(Mandatory) Path to the second RESTBL file to merge')

    # Arguments for 'generate-changelog' action
    gen_changelog_group = parser.add_argument_group('generate-changelog')
    gen_changelog_group.add_argument('--changelog-restbl-path', type=str, help='(Mandatory) Path to the RESTBL file for generating changelog')
    gen_changelog_group.add_argument('--format', choices=['json', 'rcl', 'yaml'], help='(Mandatory) Format of the changelog')

    # Arguments for 'apply-patches' action
    apply_patches_group = parser.add_argument_group('apply-patches')
    apply_patches_group.add_argument('--patch-restbl', type=str, help='(Mandatory) Path to the RESTBL file to patch')
    apply_patches_group.add_argument('--patches-path', type=str, help='(Mandatory) Path to the folder containing patches (rcl, yaml, json)')

    args = parser.parse_args()

    if args.action == 'merge-mods':
        if args.restbl_path is None:
            restbl_path = ''  # Set restbl_path to an empty string if it's not provided
        else:
            restbl_path = args.restbl_path
        import time
        start_time = time.time()
        MergeMods(args.mod_path, restbl_path, args.version, args.compress, args.delete_existing_restbl, args.use_existing_restbl, args.use_checksums)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"The script executed in {execution_time} seconds")
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
    if args.action == 'generate-changelog':
        gen_changelog(args.changelog_restbl_path, args.format)
    elif args.action == 'apply-patches':
        apply_patches(args.patch_restbl, args.patches_path, compressed=args.compress)

if __name__ == "__main__":
    open_tool()

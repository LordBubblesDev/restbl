import zstandard as zs
import sarc
import os
import io
import sys

def get_correct_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class Zstd:
    # Initialize class variable for dictionaries
    dictionaries = None
    pack_zsdic = None
    bcett_byml_zsdic = None
    zs_zsdic = None

    # Initialize decompressor
    def __init__(self, format=zs.FORMAT_ZSTD1): # zs.FORMAT_ZSTD1_MAGICLESS for headerless
        self.format = format
        self.decompressor = zs.ZstdDecompressor()

        # Load dictionaries only if they haven't been loaded before
        if Zstd.dictionaries is None:
            zs_dic_path = "dic/zsdic"
            zs_dic_path = get_correct_path(zs_dic_path)
            with open(os.path.join(zs_dic_path), 'rb') as file:
                data = file.read()
            dictionaries = self.decompressor.decompress(data)
            Zstd.dictionaries = sarc.Sarc(dictionaries).files

            # Cache the three files
            for dic in Zstd.dictionaries:
                if dic["Name"] == 'pack.zsdic':
                    Zstd.pack_zsdic = dic["Data"]
                elif dic["Name"] == 'bcett.byml.zsdic':
                    Zstd.bcett_byml_zsdic = dic["Data"]
                elif dic["Name"] == 'zs.zsdic':
                    Zstd.zs_zsdic = dic["Data"]

    # Decompresses specified file to specified location
    def _DecompressFile(self, filepath, output_dir='', with_dict=False, no_output=False):
        if with_dict and os.path.basename(filepath) != 'ZsDic.pack.zs':
            if os.path.splitext(os.path.splitext(filepath)[0])[1] == '.pack':
                dictionary = Zstd.pack_zsdic
            elif os.path.splitext(os.path.splitext(filepath)[0])[1] == '.byml':
                if filepath.endswith('.bcett.byml.zs'):
                    dictionary = Zstd.bcett_byml_zsdic
                else:
                    dictionary = Zstd.zs_zsdic
            else:
                dictionary = Zstd.zs_zsdic
            self.decompressor = zs.ZstdDecompressor(zs.ZstdCompressionDict(dictionary), format=self.format)
        else:
            self.decompressor = zs.ZstdDecompressor(format=self.format)
        with open(filepath, 'rb') as file:
            data = file.read()
        if os.path.splitext(filepath)[1] in ['.zs', '.zstd']:
            filepath = os.path.splitext(filepath)[0]
        else:
            return
        try:
            decompressed_data = self.decompressor.decompress(data)
        except zs.ZstdError as e:
            print(f"Error decompressing file {filepath}: {e}")
            return None
        if not(no_output):
            with open(os.path.join(output_dir, os.path.basename(filepath)), 'wb') as file:
                file.write(decompressed_data)
        return decompressed_data

    # Decompresses a file or directory
    def Decompress(self, filepath, output_dir='', with_dict=True, no_output=False):
        if os.path.isfile(filepath):
            return self._DecompressFile(filepath, output_dir, with_dict, no_output)
        elif os.path.isdir(filepath):
            for root_dir, dir, files in os.walk(filepath):
                for file in files:
                    if os.path.isfile(os.path.join(root_dir, file)):
                        rel_path = os.path.relpath(root_dir, filepath)
                        if not(os.path.exists(os.path.join(output_dir, rel_path))):
                            os.makedirs(os.path.join(output_dir, rel_path))
                        return self._DecompressFile(os.path.join(root_dir, file), os.path.join(output_dir, rel_path), with_dict, no_output)

    # Get size of decompressed file
    def GetDecompressedSize(self, filepath, with_dict=True):
        with open(filepath, 'rb') as file:
            if os.path.splitext(filepath)[1] in ['.zs', '.zstd']:
                if os.path.splitext(filepath)[1] == '.mc':
                    file.seek(0xc)
                data = file.read()
                if with_dict:
                    if os.path.splitext(os.path.splitext(filepath)[0])[1] == '.pack':
                        dictionary = Zstd.pack_zsdic
                    elif os.path.splitext(os.path.splitext(filepath)[0])[1] == '.byml':
                        if filepath.endswith('.bcett.byml.zs'):
                            dictionary = Zstd.bcett_byml_zsdic
                        else:
                            dictionary = Zstd.zs_zsdic
                    else:
                        dictionary = Zstd.zs_zsdic
                    self.decompressor = zs.ZstdDecompressor(zs.ZstdCompressionDict(dictionary), format=self.format)
                else:
                    self.decompressor = zs.ZstdDecompressor(format=self.format)
                return len(self.decompressor.decompress(data))
            else:
                file.seek(0, io.SEEK_END)
                return file.tell()

    # Compresses file to specified location
    def _CompressFile(self, filepath, output_dir='', level=16, with_dict=False):
        if with_dict and os.path.basename(filepath) != 'ZsDic.pack.zs':
            if filepath.endswith('.pack'):
                dictionary = Zstd.pack_zsdic
            elif filepath.endswith('.byml'):
                if filepath.endswith('.bcett.byml'):
                    dictionary = Zstd.bcett_byml_zsdic
                else:
                    dictionary = Zstd.zs_zsdic
            else:
                dictionary = Zstd.zs_zsdic
            self.compressor = zs.ZstdCompressor(level, zs.ZstdCompressionDict(dictionary))
        else:
            self.compressor = zs.ZstdCompressor(level)
        with open(filepath, 'rb') as file:
            data = file.read()
        filepath += '.zs'
        with open(os.path.join(output_dir, os.path.basename(filepath)), 'wb') as file:
            if self.format == zs.FORMAT_ZSTD1_MAGICLESS:
                file.write(self.compressor.compress(data)[4:])
                return self.compressor.compress(data)[4:]
            else:
                file.write(self.compressor.compress(data))
                return self.compressor.compress(data)
    
    # Compresses file or files and maintains directory structure
    def Compress(self, filepath, output_dir='', level=16, with_dict=True):
        if os.path.isfile(filepath):
            return self._CompressFile(filepath, output_dir, level, with_dict)
        elif os.path.isdir(filepath):
            for root_dir, dir, files in os.walk(filepath):
                for file in files:
                    if os.path.isfile(os.path.join(root_dir, file)):
                        rel_path = os.path.relpath(root_dir, filepath)
                        if not(os.path.exists(os.path.join(output_dir, rel_path))):
                            os.makedirs(os.path.join(output_dir, rel_path))
                        return self._CompressFile(os.path.join(root_dir, file), os.path.join(output_dir, rel_path), level, with_dict)

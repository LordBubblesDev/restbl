from byml import *
from utils import *
import mmh3
from zstd import Zstd
import os
import math

# Includes a few presets for common sets of flags (such as adding new enemies, new materials)
# If you want to make your own presets, use the Int, UInt, Long, ULong, Float, and Double classes for numerical values
# Do not use the built-in Python types for those - there are strict typing requirements and we need to preserve those

# Data types found in GameDataList
valid_types = [
    'Bool',
    'BoolArray',
    'Int',
    'IntArray',
    'Float',
    'FloatArray',
    'Enum',
    'EnumArray',
    'Vector2',
    'Vector2Array',
    'Vector3',
    'Vector3Array',
    'String16',
    'String16Array',
    'String32',
    'String32Array',
    'String64',
    'String64Array',
    'Binary',
    'BinaryArray',
    'UInt',
    'UIntArray',
    'Int64',
    'Int64Array',
    'UInt64',
    'UInt64Array',
    'WString16',
    'WString16Array',
    'WString32',
    'WString32Array',
    'WString64',
    'WString64Array',
    'Struct',
    'BoolExp',
    'Bool64bitKey'
]

# ResetTypeValue - pass these as arguments to GetResetType to calculate the value
reset_types = {
    "OnSceneChange" : 0,
    "OnGameDayChange" : 1,
    "OptionsReset" : 2,
    "OnBloodMoon" : 3,
    "OnStartNewData" : 4,
    "OnGameDayChangeRandom" : 5,
    "OnSceneInitialize" : 6,
    "ZonauEnemyRespawnTimer" : 7,
    "RandomRevival" : 8,
    "OnStartNewDataOnly" : 9
}

class Gamedata:
    def __init__(self, self_path):
        print("Initializing GameData...")
        self.gamedata = Byml(self_path)
        print("Initialization complete")

    def CalculateAndUpdateMetadata(self):
        print("Calculating SaveDataSize and updating metadata")
        sizes = []
        offsets = []
        for i in range(7):  # Assuming there are 7 indices to calculate
            size, offset = self.calc(i)
            sizes.append(size)
            offsets.append(offset)
        size = 0x20
        offset = 0x20
        for datatype in valid_types:
            if datatype == "Struct" or datatype == "BoolExp":
                continue
            size += 8
            offset += 8
            if datatype == "Bool64bitKey":
                size += 8
                offset += 8
            has_keys = False
            if datatype in self.gamedata.root_node["Data"]:
                for entry in self.gamedata.root_node["Data"][datatype]:
                    if datatype == "Bool64bitKey":
                        has_keys = True
                    else:
                        offset += 8
                    size += self.get_size(datatype, entry)
            if has_keys:
                size += 8

        metadata = {
            "AllDataSaveOffset": Int(offset),
            "AllDataSaveSize": Int(size),
            "FormatVersion": Int(1),
            "SaveDataOffsetPos": [Int(i) for i in offsets],
            "SaveDataSize": [Int(i) for i in sizes],
            "SaveDirectory": self.gamedata.root_node["MetaData"]["SaveDirectory"],
            "SaveTypeHash": self.gamedata.root_node["MetaData"]["SaveTypeHash"]
        }
        self.gamedata.root_node["MetaData"].update(metadata)

    def calc(self, index):
        if self.gamedata.root_node["MetaData"]["SaveDirectory"][index] != "":
            size = 0x20
            offset = 0x20
            for datatype in valid_types:
                size += 8
                offset += 8
                if datatype == "Bool64bitKey":
                    size += 8
                    offset += 8
                has_keys = False
                if datatype == "Struct" or datatype == "BoolExp":
                    continue
                if datatype in self.gamedata.root_node["Data"]:
                    for entry in self.gamedata.root_node["Data"][datatype]:
                        if entry["SaveFileIndex"] == index:
                            if datatype == "Bool64bitKey":
                                has_keys = True
                            else:
                                offset += 8
                            size += self.get_size(datatype, entry)
                if has_keys:
                    size += 8
        else:
            size = 0
            offset = 0
        return size, offset

    def get_size(self, datatype, entry):
        size = 8
        try:
            if "Array" in datatype:
                size += 4
                if "ArraySize" in entry:
                    n = entry["ArraySize"]
                elif "Size" in entry:
                    n = entry["Size"]
                elif isinstance(entry["DefaultValue"], list):
                    n = len(entry["DefaultValue"])
                else:
                    raise ValueError("Could not determine array size")
            else:
                n = 1

            if datatype in ["Bool", "Int", "UInt", "Float", "Enum"]:
                pass
            elif datatype == "BoolArray":
                size += math.ceil((4 if math.ceil(n / 8) < 4 else math.ceil(n / 8)) / 4) * 4
            elif datatype in ["IntArray", "FloatArray", "UIntArray", "EnumArray"]:
                size += n * 4
            elif "Vector2" in datatype:
                size += n * 8
            elif "Vector3" in datatype:
                size += n * 12
            elif "WString16" in datatype:
                size += n * 32
            elif "WString32" in datatype:
                size += n * 64
            elif "WString64" in datatype:
                size += n * 128
            elif "String16" in datatype:
                size += n * 16
            elif "String32" in datatype:
                size += n * 32
            elif "String64" in datatype:
                size += n * 64
            elif "Int64" in datatype or "UInt64" in datatype:
                size += n * 8
            elif datatype == "Bool64bitKey":
                pass
            elif "Binary" in datatype:
                size += n * 4
                size += n * entry["DefaultValue"]
            else:
                raise ValueError(f"Invalid Type: {datatype}")
        except Exception as e:
            print(f"Error processing datatype '{datatype}' with entry '{entry}': {str(e)}")
            raise
        return size

    def Save(self, output_dir=''):
        print("Saving changes... (may take a moment so please be patient)")
        self.gamedata.root_node["Data"]["Bool64bitKey"] = sorted(self.gamedata.root_node["Data"]["Bool64bitKey"], key=lambda d: d["Hash"])
        self.gamedata.Reserialize(output_dir)
        print("Saved")

    # Returns flag entry
    def GetFlag(self, name, datatype):
        hash = self.GetHash(name)
        flag = self.IterTryFindFlagByType(hash, datatype)
        return flag

    # Returns flag entry from flag name of a flag in a struct
    def GetStructFlag(self, name, struct_name):
        name_hash = self.GetHash(name)
        struct_hash = self.GetHash(struct_name)
        struct = self.IterTryFindFlagByType(struct_hash, "Struct")
        if struct is None:
            print(f"Struct {struct_name} not found")
            return None
        hash = 0
        for entry in struct["DefaultValue"]:
            if name_hash == entry["Hash"]:
                hash = entry["Value"]
        if hash == 0:
            print(f"Flag {name} was not found in {struct_name}")
            return None
        flag = self.IterTryFindFlag(hash)
        return flag

    # Sets/adds flag of the specified type
    def SetFlag(self, datatype, new_flag):
        if datatype not in valid_types:
            raise ValueError(f"Invalid type {datatype}")
        if datatype == "BinaryArray":
            assert len(new_flag) == 6, "Invalid entry"
            assert set(list(new_flag.keys())) == {"ArraySize", "DefaultValue",
                                                  "Hash", "OriginalSize",
                                                  "ResetTypeValue", "SaveFileIndex"}, "Invalid entry"
        hash = new_flag["Hash"]
        if datatype not in self.gamedata.root_node["Data"]:
            self.gamedata.root_node[datatype] = []
        for i in range(len(self.gamedata.root_node["Data"][datatype])):
            if self.gamedata.root_node["Data"][datatype][i]["Hash"] == hash:
                self.gamedata.root_node["Data"][datatype][i] = new_flag
                return
        self.gamedata.root_node["Data"][datatype].append(new_flag)

    # Not for EnumArray
    def SetArrayValueByIndexAndType(self, array_name, index, value, datatype):
        hash = self.GetHash(array_name)
        if datatype not in valid_types or "Array" not in datatype:
            raise ValueError("Invalid array type")
        if "Bool" in datatype:
            if not(isinstance(value, bool)):
                raise ValueError("Invalid value")
        if "Int" in datatype:
            if not(isinstance(value, Int)):
                raise ValueError("Invalid value")
        if "Float" in datatype:
            if not(isinstance(value, Float)):
                raise ValueError("Invalid value")
        if "Vector" in datatype:
            if not(isinstance(value, dict)):
                raise ValueError("Invalid value")
        if "String" in datatype:
            if not(isinstance(value, str)):
                raise ValueError("Invalid value")
        if "UInt" in datatype:
            if not(isinstance(value, UInt)):
                raise ValueError("Invalid value")
        if "Int64" in datatype:
            if not(isinstance(value, Long)):
                raise ValueError("Invalid value")
        if "UInt64" in datatype:
            if not(isinstance(value, ULong)):
                raise ValueError("Invalid value")
        for i in range(len(self.gamedata.root_node["Data"][datatype])):
            if self.gamedata.root_node["Data"][datatype][i]["Hash"] == hash:
                self.gamedata.root_node["Data"][datatype][i]["DefaultValue"][index] = value
                return
        raise ValueError("Unable to set array value")
    
    # Sets/adds Bool64bitKey entry
    def SetBoolKey(self, entry):
        assert len(entry) in [3, 4], "Invalid entry"
        assert "ResetTypeValue" in entry and "Hash" in entry and "SaveFileIndex" in entry, "Invalid entry"
        if entry["ResetTypeValue"] & (2 ** 8):
            assert "ExtraByte" in entry, "Material respawning entries need an ExtraByte value"
        assert type(entry["Hash"] == ULong), "Hashes must be a unsigned long (64-bits)"
        for i in range(len(self.gamedata.root_node["Data"]["Bool64bitKey"])):
            if self.gamedata.root_node["Data"]["Bool64bitKey"][i]["Hash"] == entry["Hash"]:
                self.gamedata.root_node["Data"]["Bool64bitKey"][i] = entry
                return
        self.gamedata.root_node["Data"]["Bool64bitKey"].append(entry)

    # Adds entry to struct
    def AddEntryToStruct(self, entry, struct_name):
        assert len(entry) == 2, "Invalid entry"
        assert set(list(entry.keys())) == {"Hash", "Value"}, "Invalid entry"
        hash = self.GetHash(struct_name)
        matched = False
        for i in range(len(self.gamedata.root_node["Data"]["Struct"])):
            if self.gamedata.root_node["Data"]["Struct"][i]["Hash"] == hash:
                for j in range(len(self.gamedata.root_node["Data"]["Struct"][i]["DefaultValue"])):
                    if self.gamedata.root_node["Data"]["Struct"][i]["DefaultValue"][j] == entry:
                        matched = True
                        break
                if not(matched):
                    self.gamedata.root_node["Data"]["Struct"][i]["DefaultValue"].append(entry)
                return
        raise ValueError("Struct not found")

    # Find flag by hash and type
    def IterTryFindFlagByType(self, hash, datatype):
        if datatype not in valid_types:
            raise ValueError(f"Invalid type {datatype}")
        if datatype not in self.gamedata.root_node["Data"]:
            return None
        else:
            for entry in self.gamedata.root_node["Data"][datatype]:
                if entry["Hash"] == hash:
                    return entry
        return None
    
    # Find flag without knowing type, returns first result
    def IterTryFindFlag(self, hash):
        for datatype in valid_types:
            result = self.IterTryFindFlagByType(hash, datatype)
            if result is not None:
                return result
        return None
    
    # If you ever need to reference this
    def GetSaveDirectories(self):
        return self.gamedata.root_node["MetaData"]["SaveDirectory"]
    
    @staticmethod
    def GetHash(value):
        if isinstance(value, int):
            return UInt(value)
        elif isinstance(value, UInt):
            return value
        elif isinstance(value, str):
            return UInt(mmh3.hash(value, signed=False))
        raise ValueError("Invalid value")
    
    @staticmethod
    def GetResetType(types):
        value = 0
        for reset_type in types:
            value = value | (2 ** reset_type)
        return Int(value)
    
    @staticmethod
    def GetExtraByte(map_unit):
        letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']
        if len(map_unit) != 2 or not(isinstance(map_unit, str)):
            raise ValueError("Invalid map unit - should be in a form such as F5")
        if map_unit[0] not in letters:
            raise ValueError("Out of range (A1 - J8)")
        if not(map_unit[1].isdigit()) or int(map_unit[1]) not in range(9):
            raise ValueError("Out of range (A1 - J8)")
        return Int(letters.index(map_unit[0]) + 10 * (int(map_unit[1]) - 1) + 1)

    # these are just a few presets for common sets of flags you may need to add to gamedata
    def AddPictureBookData(self, actor_name):
        struct = {
        "DefaultValue": [
            {
            "Hash": self.GetHash("IsNew"),
            "Value": self.GetHash(f"PictureBookData.{actor_name}.IsNew")
            },
            {
            "Hash": self.GetHash("State"),
            "Value": self.GetHash(f"PictureBookData.{actor_name}.State")
            }
        ],
        "Hash": self.GetHash(f"PictureBookData.{actor_name}"),
        "ResetTypeValue": Int(0),
        "SaveFileIndex": Int(-1)
        }
        isnew = {
        "DefaultValue": False,
        "Hash": self.GetHash(f"PictureBookData.{actor_name}.IsNew"),
        "ResetTypeValue": Int(80),
        "SaveFileIndex": Int(0)
        }
        state = {
        "DefaultValue": self.GetHash("Unopened"),
        "Hash": self.GetHash(f"PictureBookData.{actor_name}.State"),
        "RawValues": [
            "Unopened",
            "TakePhoto",
            "Buy"
        ],
        "ResetTypeValue": Int(80),
        "SaveFileIndex": Int(0),
        "Values": [
            self.GetHash("Unopened"),
            self.GetHash("TakePhoto"),
            self.GetHash("Buy")
        ]
        }
        self.SetFlag("Struct", struct)
        self.SetFlag("Bool", isnew)
        self.SetFlag("Enum", state)
        self.AddEntryToStruct({"Hash" : self.GetHash(actor_name),
                               "Value" : self.GetHash(f"PictureBookData.{actor_name}")}, "PictureBookData")

    def AddRecipeFlags(self, actor_name):
        struct = {
            "DefaultValue": [
                {
                    "Hash": self.GetHash("IsNew"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.IsNew")
                },
                {
                    "Hash": self.GetHash("LatestLogIndex"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.LatestLogIndex")
                },
                {
                    "Hash": self.GetHash("RecipeLog"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog")
                },
                {
                    "Hash": self.GetHash("IsCooked"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.IsCooked")
                }
            ],
            "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}"),
            "ResetTypeValue": Int(0),
            "SaveFileIndex": Int(-1)
        }
        recipelog = {
            "DefaultValue": [
                {
                    "Hash": self.GetHash("LogIndex"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.LogIndex")
                },
                {
                    "Hash": self.GetHash("Materials"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.Materials")
                },
                {
                    "Hash": self.GetHash("Effect"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.Effect")
                },
                {
                    "Hash": self.GetHash("EffectLevel"),
                    "Value": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.EffectLevel")
                }
            ],
            "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog"),
            "ResetTypeValue": Int(0),
            "SaveFileIndex": Int(-1),
            "Size": UInt(5)
        }
        recipelogmaterials = {
        "DefaultValue": ["" for i in range(25)],
        "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.Materials"),
        "OriginalSize": UInt(5),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        logindex = {
        "DefaultValue": [Int(-1) for i in range(5)],
        "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.LogIndex"),
        "OriginalSize": UInt(1),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        effectlevel = {
        "DefaultValue": [Int(0) for i in range(5)],
        "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.EffectLevel"),
        "OriginalSize": UInt(1),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        effect = {
        "DefaultValue": self.GetHash("None"),
        "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.RecipeLog.Effect"),
        "OriginalSize": UInt(1),
        "RawValues": [
            "None",
            "ResistHot",
            "ResistBurn",
            "ResistCold",
            "ResistElectric",
            "ResitLightning",
            "ResistFreeze",
            "ResistAncient",
            "SwimSpeedUp",
            "DecreaseSwimStamina",
            "SpinAttack",
            "ClimbWaterfall",
            "ClimbSpeedUp",
            "ClimbSpeedUpOnlyHorizontaly",
            "AttackUp",
            "AttackUpCold",
            "AttackUpHot",
            "AttackUpThunderstorm",
            "AttackUpDark",
            "AttackUpBone",
            "QuietnessUp",
            "SandMoveUp",
            "SnowMoveUp",
            "WakeWind",
            "TwiceJump",
            "EmergencyAvoid",
            "DefenseUp",
            "AllSpeed",
            "MiasmaGuard",
            "MaskBokoblin",
            "MaskMoriblin",
            "MaskLizalfos",
            "MaskLynel",
            "YigaDisguise",
            "StalDisguise",
            "LifeRecover",
            "LifeMaxUp",
            "StaminaRecover",
            "ExStaminaMaxUp",
            "LifeRepair",
            "DivingMobilityUp",
            "NotSlippy",
            "Moisturizing",
            "LightEmission",
            "RupeeGuard",
            "FallResist",
            "SwordBeamUp",
            "VisualizeLife",
            "NightMoveSpeedUp",
            "NightGlow",
            "DecreaseWallJumpStamina",
            "DecreaseChargeAttackStamina",
            "EmitTerror",
            "NoBurning",
            "NoFallDamage",
            "NoSlip",
            "RupeeGuardRate",
            "MaskAll",
            "DecreaseZonauEnergy",
            "ZonauEnergyHealUp",
            "MaskHorablin",
            "MiasmaDefenseUp",
            "ChargePowerUpCold",
            "ChargePowerUpHot",
            "ChargePowerUpThunderstorm",
            "LightFootprint",
            "SoulPowerUpLightning",
            "SoulPowerUpWater",
            "SoulPowerUpWind",
            "SoulPowerUpFire",
            "SoulPowerUpSpirit",
            "EnableUseSwordBeam"
        ],
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0),
        "Size": UInt(5),
        "Values": [
            ULong(self.GetHash("None")),
            ULong(self.GetHash("ResistHot")),
            ULong(self.GetHash("ResistBurn")),
            ULong(self.GetHash("ResistCold")),
            ULong(self.GetHash("ResistElectric")),
            ULong(self.GetHash("ResitLightning")),
            ULong(self.GetHash("ResistFreeze")),
            ULong(self.GetHash("ResistAncient")),
            ULong(self.GetHash("SwimSpeedUp")),
            ULong(self.GetHash("DecreaseSwimStamina")),
            ULong(self.GetHash("SpinAttack")),
            ULong(self.GetHash("ClimbWaterfall")),
            ULong(self.GetHash("ClimbSpeedUp")),
            ULong(self.GetHash("ClimbSpeedUpOnlyHorizontaly")),
            ULong(self.GetHash("AttackUp")),
            ULong(self.GetHash("AttackUpCold")),
            ULong(self.GetHash("AttackUpHot")),
            ULong(self.GetHash("AttackUpThunderstorm")),
            ULong(self.GetHash("AttackUpDark")),
            ULong(self.GetHash("AttackUpBone")),
            ULong(self.GetHash("QuietnessUp")),
            ULong(self.GetHash("SandMoveUp")),
            ULong(self.GetHash("SnowMoveUp")),
            ULong(self.GetHash("WakeWind")),
            ULong(self.GetHash("TwiceJump")),
            ULong(self.GetHash("EmergencyAvoid")),
            ULong(self.GetHash("DefenseUp")),
            ULong(self.GetHash("AllSpeed")),
            ULong(self.GetHash("MiasmaGuard")),
            ULong(self.GetHash("MaskBokoblin")),
            ULong(self.GetHash("MaskMoriblin")),
            ULong(self.GetHash("MaskLizalfos")),
            ULong(self.GetHash("MaskLynel")),
            ULong(self.GetHash("YigaDisguise")),
            ULong(self.GetHash("StalDisguise")),
            ULong(self.GetHash("LifeRecover")),
            ULong(self.GetHash("LifeMaxUp")),
            ULong(self.GetHash("StaminaRecover")),
            ULong(self.GetHash("ExStaminaMaxUp")),
            ULong(self.GetHash("LifeRepair")),
            ULong(self.GetHash("DivingMobilityUp")),
            ULong(self.GetHash("NotSlippy")),
            ULong(self.GetHash("Moisturizing")),
            ULong(self.GetHash("LightEmission")),
            ULong(self.GetHash("RupeeGuard")),
            ULong(self.GetHash("FallResist")),
            ULong(self.GetHash("SwordBeamUp")),
            ULong(self.GetHash("VisualizeLife")),
            ULong(self.GetHash("NightMoveSpeedUp")),
            ULong(self.GetHash("NightGlow")),
            ULong(self.GetHash("DecreaseWallJumpStamina")),
            ULong(self.GetHash("DecreaseChargeAttackStamina")),
            ULong(self.GetHash("EmitTerror")),
            ULong(self.GetHash("NoBurning")),
            ULong(self.GetHash("NoFallDamage")),
            ULong(self.GetHash("NoSlip")),
            ULong(self.GetHash("RupeeGuardRate")),
            ULong(self.GetHash("MaskAll")),
            ULong(self.GetHash("DecreaseZonauEnergy")),
            ULong(self.GetHash("ZonauEnergyHealUp")),
            ULong(self.GetHash("MaskHorablin")),
            ULong(self.GetHash("MiasmaDefenseUp")),
            ULong(self.GetHash("ChargePowerUpCold")),
            ULong(self.GetHash("ChargePowerUpHot")),
            ULong(self.GetHash("ChargePowerUpThunderstorm")),
            ULong(self.GetHash("LightFootprint")),
            ULong(self.GetHash("SoulPowerUpLightning")),
            ULong(self.GetHash("SoulPowerUpWater")),
            ULong(self.GetHash("SoulPowerUpWind")),
            ULong(self.GetHash("SoulPowerUpFire")),
            ULong(self.GetHash("SoulPowerUpSpirit")),
            ULong(self.GetHash("EnableUseSwordBeam"))
        ]
        }
        self.SetFlag("Struct", struct)
        self.SetFlag("Struct", recipelog)
        self.SetFlag("String64Array", recipelogmaterials)
        self.SetFlag("IntArray", logindex)
        self.SetFlag("IntArray", effectlevel)
        self.SetFlag("EnumArray", effect)
        self.AddEntryToStruct({"Hash" : self.GetHash(actor_name),
                               "Value" : self.GetHash(f"RecipeCard.Content.{actor_name}")}, "RecipeCard.Content")
        self.AddEntryToStruct({"Hash" : self.GetHash(actor_name),
                            "Value" : self.GetHash(f"IsGetAnyway.{actor_name}")}, "IsGetAnyway")
        self.AddEntryToStruct({"Hash" : self.GetHash(actor_name),
                            "Value" : self.GetHash(f"IsGet.{actor_name}")}, "IsGet")
        latestlogindex = {
        "DefaultValue": Int(-1),
        "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.LatestLogIndex"),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        iscooked = {
        "DefaultValue": False,
        "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.IsCooked"),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        isnew = {
        "DefaultValue": False,
        "Hash": self.GetHash(f"RecipeCard.Content.{actor_name}.IsNew"),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        isget = {
        "DefaultValue": False,
        "Hash": self.GetHash(f"IsGet.{actor_name}"),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        isgetanyway = {
        "DefaultValue": False,
        "Hash": self.GetHash(f"IsGetAnyway.{actor_name}"),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        self.SetFlag("Int", latestlogindex)
        self.SetFlag("Bool", iscooked)
        self.SetFlag("Bool", isnew)
        self.SetFlag("Bool", isget)
        self.SetFlag("Bool", isgetanyway)

    def AddBattleData(self, actor_name):
        struct = {
            "DefaultValue": [
                {
                "Hash": self.GetHash("GuardJustCount"),
                "Value": self.GetHash(f"EnemyBattleData.{actor_name}.GuardJustCount")
                },
                {
                "Hash": self.GetHash("JustAvoidCount"),
                "Value": self.GetHash(f"EnemyBattleData.{actor_name}.JustAvoidCount")
                },
                {
                "Hash": self.GetHash("DefeatedNoDamageCount"),
                "Value": self.GetHash(f"EnemyBattleData.{actor_name}.DefeatedNoDamageCount")
                },
                {
                "Hash": self.GetHash("HeadShotCount"),
                "Value": self.GetHash(f"EnemyBattleData.{actor_name}.HeadShotCount")
                }
            ],
            "Hash": self.GetHash(f"EnemyBattleData.{actor_name}"),
            "ResetTypeValue": Int(0),
            "SaveFileIndex": Int(-1)
            }
        guardjust = {
            "DefaultValue": Int(0),
            "Hash": self.GetHash(f"EnemyBattleData.{actor_name}.GuardJustCount"),
            "ResetTypeValue": Int(80),
            "SaveFileIndex": Int(0)
        }
        justavoid = {
            "DefaultValue": Int(0),
            "Hash": self.GetHash(f"EnemyBattleData.{actor_name}.JustAvoidCount"),
            "ResetTypeValue": Int(80),
            "SaveFileIndex": Int(0)
        }
        nodmg = {
            "DefaultValue": Int(0),
            "Hash": self.GetHash(f"EnemyBattleData.{actor_name}.DefeatedNoDamageCount"),
            "ResetTypeValue": Int(80),
            "SaveFileIndex": Int(0)
        }
        headshot = {
            "DefaultValue": Int(0),
            "Hash": self.GetHash(f"EnemyBattleData.{actor_name}.HeadShotCount"),
            "ResetTypeValue": Int(80),
            "SaveFileIndex": Int(0)
        }
        self.SetFlag("Struct", struct)
        self.SetFlag("Int", guardjust)
        self.SetFlag("Int", justavoid)
        self.SetFlag("Int", nodmg)
        self.SetFlag("Int", headshot)
        self.AddEntryToStruct({"Hash" : self.GetHash(actor_name),
                               "Value" : self.GetHash(f"EnemyBattleData.{actor_name}")}, "EnemyBattleData")

    def AddEnemyFlags(self, enemy_name):
        print(f"Adding {enemy_name} flags...")
        self.AddPictureBookData(enemy_name)
        self.AddBattleData(enemy_name)
        self.AddEntryToStruct({"Hash" : self.GetHash(enemy_name),
                               "Value" : self.GetHash(f"DefeatedEnemyNum.{enemy_name}")}, "DefeatedEnemyNum")
        self.SetFlag("Int", {"DefaultValue": Int(0), "Hash": self.GetHash(f"DefeatedEnemyNum.{enemy_name}"),
                            "ResetTypeValue": Int(80), "SaveFileIndex": Int(0)})

    def AddMaterialFlags(self, material_name, throwable=True):
        print(f"Adding {material_name} flags...")
        self.AddPictureBookData(material_name)
        self.AddEntryToStruct({"Hash" : self.GetHash(material_name),
                            "Value" : self.GetHash(f"IsGetAnyway.{material_name}")}, "IsGetAnyway")
        self.AddEntryToStruct({"Hash" : self.GetHash(material_name),
                            "Value" : self.GetHash(f"IsGet.{material_name}")}, "IsGet")
        isget = {
        "DefaultValue": False,
        "Hash": self.GetHash(f"IsGet.{material_name}"),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        isgetanyway = {
        "DefaultValue": False,
        "Hash": self.GetHash(f"IsGetAnyway.{material_name}"),
        "ResetTypeValue": Int(16),
        "SaveFileIndex": Int(0)
        }
        self.SetFlag("Bool", isget)
        self.SetFlag("Bool", isgetanyway)
        if throwable:
            self.AddEntryToStruct({"Hash" : self.GetHash(material_name),
                               "Value" : self.GetHash(f"MaterialShortCutCounter.{material_name}")}, "MaterialShortCutCounter")
            self.SetFlag("UInt", {"DefaultValue": UInt(0), "Hash": self.GetHash(f"MaterialShortCutCounter.{material_name}"),
                                    "ResetTypeValue": Int(16), "SaveFileIndex": Int(0)})


import customtkinter as ctk
from tkinter import scrolledtext, filedialog, PhotoImage, Toplevel, Checkbutton, IntVar, Button
import tkinter.messagebox as messagebox
from icon import images

ctk.set_appearance_mode("dark")

import customtkinter as ctk

class ResetTypeDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Reset Types")
        self.geometry("270x400")
        if os.name == 'nt':
            self.iconbitmap(images)
        else:
            icon = PhotoImage(file=images)
            self.iconphoto(True, icon)
        self.reset_type_vars = {}
        self.selected_reset_types = []

        # Make the dialog modal and always on top
        self.transient(parent)
        self.grab_set()

        # Create a frame to hold the checkboxes and center it
        checkbox_frame = ctk.CTkFrame(self)
        checkbox_frame.pack(pady=20, padx=20, fill='both', expand=True)

        # Access the global reset_types directly
        default_checked = ["OnStartNewData", "OnSceneInitialize"]
        for i, (reset_type, _) in enumerate(reset_types.items()):
            is_checked = 1 if reset_type in default_checked else 0
            var = ctk.IntVar(value=is_checked)
            cb = ctk.CTkCheckBox(checkbox_frame, text=reset_type, variable=var)
            cb.pack(pady=2, padx=10, anchor='w')  # Pack with some padding, anchor west for alignment
            self.reset_type_vars[reset_type] = var

        # OK button to close the dialog and apply selections
        ok_button = ctk.CTkButton(self, text="OK", command=self.on_ok)
        ok_button.pack(pady=20, padx=20)

    def on_ok(self):
        # Collect all selected reset types
        self.selected_reset_types.clear()  # Clear previous selections
        for reset_type, var in self.reset_type_vars.items():
            if var.get() == 1:
                self.selected_reset_types.append(reset_type)
        self.destroy()

class GamedataUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("GameData Flags Generator")
        self.geometry("620x400")
        if os.name == 'nt':
            self.iconbitmap(images)
        else:
            icon = PhotoImage(file=images)
            self.iconphoto(True, icon)

        self.placeholder_active = True
        self.equipment_respawn_var = ctk.IntVar(value=0)
        self.drop_respawn_var = ctk.IntVar(value=0)

        # Frame for the flag type selection
        self.flag_type_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.flag_type_frame.grid(row=0, column=0, pady=(10, 5), padx=20, sticky='ew')
        self.flag_type_label = ctk.CTkLabel(self.flag_type_frame, text="Select Flag Type:")
        self.flag_type_label.grid(row=0, column=0, padx=(10, 5), sticky='e')
        self.flag_type_var = ctk.StringVar(value="AddMaterialFlags")
        self.flag_type_dropdown = ctk.CTkOptionMenu(self.flag_type_frame, variable=self.flag_type_var, values=["AddMaterialFlags", "AddEnemyFlags", "AddMapItemFlags", "AddRecipeFlags"])
        self.flag_type_dropdown.grid(row=0, column=1, padx=(5, 10), sticky='w')
        self.flag_type_var.trace("w", self.update_label_text)  # Bind the update_label_text function to the variable
        self.flag_type_frame.grid_columnconfigure(0, weight=1)
        self.flag_type_frame.grid_columnconfigure(1, weight=1)

        # Frame for the checkboxes
        self.respawn_flag_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.respawn_flag_frame.grid(row=1, column=0, padx=20, pady=5, sticky='ew')
        self.respawn_flag_frame.grid_columnconfigure(0, weight=1)
        self.respawn_flag_frame.grid_columnconfigure(1, weight=1)
        self.equipment_respawn_checkbox = ctk.CTkCheckBox(master=self.respawn_flag_frame, text="Add Equipment Respawn Flag", variable=self.equipment_respawn_var)
        self.equipment_respawn_checkbox.grid(row=0, column=0, padx=10, pady=5, sticky='w')
        self.drop_respawn_checkbox = ctk.CTkCheckBox(master=self.respawn_flag_frame, text="Add Drop Respawn Flag", variable=self.drop_respawn_var)
        self.drop_respawn_checkbox.grid(row=0, column=1, padx=10, pady=5, sticky='w')

        # Frame for the input file
        self.input_file_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.input_file_frame.grid(row=2, column=0, pady=(10, 5), padx=20, sticky='ew')
        self.input_file_label = ctk.CTkLabel(self.input_file_frame, text="GameData File:")
        self.input_file_label.grid(row=0, column=0, padx=(10, 5), sticky='e')
        self.input_file_entry = ctk.CTkEntry(self.input_file_frame, width=320)
        self.input_file_entry.grid(row=0, column=1, padx=(5, 5), sticky='ew')
        self.browse_input_button = ctk.CTkButton(self.input_file_frame, text="Browse", command=self.browse_input_file)
        self.browse_input_button.grid(row=0, column=2, padx=(5, 10), sticky='w')
        self.input_file_frame.grid_columnconfigure(0, weight=1)
        self.input_file_frame.grid_columnconfigure(1, weight=1)
        self.input_file_frame.grid_columnconfigure(2, weight=1)

        # Other UI elements
        self.names_label = ctk.CTkLabel(self, text="Actor Names:")
        self.names_label.grid(row=3, column=0, pady=(10, 5), padx=20, sticky='w')
        self.names_text = scrolledtext.ScrolledText(self, height=10, bg="#2e2e2e", fg="white", insertbackground="white")
        self.names_text.grid(row=4, column=0, pady=(0, 10), padx=20, sticky='nsew')
        self.names_text.bind("<FocusIn>", self.clear_placeholder)
        self.names_text.bind("<FocusOut>", self.set_placeholder)
        self.apply_button = ctk.CTkButton(self, text="Apply Changes", command=self.apply_changes)
        self.apply_button.grid(row=5, column=0, pady=(20, 10), padx=20, sticky='ew')

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        # Initialize the example text based on the default dropdown selection
        self.update_label_text()

    def update_label_text(self, *args):
        selected_option = self.flag_type_var.get()
        if selected_option == "AddMapItemFlags":
            self.names_label.configure(text="Hashes:")
            self.set_example_text('Example:\n0x2c3649c8eeca8893\n0x6128cf221216e50b\n0x9c2f6ebb44c2c0c3\n\n(Hashes of actors placed on the map, like chests, weapons, enemies...)')
            self.equipment_respawn_checkbox.grid(row=1, column=0, pady=(10, 5), padx=20, sticky='w')
            self.drop_respawn_checkbox.grid(row=1, column=1, pady=(10, 5), padx=20, sticky='w')
            self.respawn_flag_frame.grid()
        elif selected_option == "AddMaterialFlags":
            self.names_label.configure(text="Actor Names:")
            self.set_example_text('Example:\nCustom_Weapon_Actor_999\nCustom_Armor_Actor_999\nCustom_Item_Actor_999\n\n(This can be any type of pouch item)')
            self.drop_respawn_checkbox.grid_remove()
            self.respawn_flag_frame.grid_remove()
        elif selected_option == "AddEnemyFlags":
            self.names_label.configure(text="Actor Names:")
            self.set_example_text('Example:\nEnemy_Bokoblin_Boss_Custom\nEnemy_Giant_Custom\nEnemy_Octarock_Custom')
            self.drop_respawn_checkbox.grid_remove()
            self.respawn_flag_frame.grid_remove()
        elif selected_option == "AddRecipeFlags":
            self.names_label.configure(text="Actor Names:")
            self.set_example_text('Example:\nItem_Cook_R_04\nItem_Cook_R_05\nItem_Cook_R_06')
            self.drop_respawn_checkbox.grid_remove()
            self.respawn_flag_frame.grid_remove()
        self.flag_type_dropdown.focus_set()

    def set_example_text(self, text):
        self.example_text = text
        if self.placeholder_active:  # Only reset the placeholder if it's currently active
            self.set_placeholder()

    def set_placeholder(self, event=None):
        if not self.names_text.get('1.0', 'end').strip() or self.placeholder_active:
            self.names_text.delete('1.0', 'end')  # Clear existing text
            self.names_text.insert('1.0', self.example_text)
            self.names_text.configure(fg='#b1b1b1')  # Set the text color to light grey (semi-transparent effect)
            self.placeholder_active = True

    def clear_placeholder(self, event=None):
        if self.placeholder_active:
            self.names_text.delete('1.0', 'end')
            self.names_text.configure(fg='white')  # Set the text color back to white
            self.placeholder_active = False

    def set_placeholder_on_focusout(self, event=None):
        if not self.names_text.get('1.0', 'end').strip():  # Check if the text field is empty
            self.set_placeholder()

    def update_checkboxes_visibility(self, flag_type):
        if flag_type == "AddMapItemFlags":
            self.equipment_respawn_checkbox.grid()
            self.drop_respawn_checkbox.grid()
        else:
            self.equipment_respawn_checkbox.grid_remove()
            self.drop_respawn_checkbox.grid_remove()

    def browse_input_file(self):
        filename = filedialog.askopenfilename(title="Select GameData File",
                                              filetypes=(("GameDataList files", ".byml.zs"), ("All files", "*.*")))
        self.input_file_entry.delete(0, ctk.END)
        self.input_file_entry.insert(0, filename)

    def apply_changes(self):
        input_path = self.input_file_entry.get()
        output_dir = os.getcwd()  # Set output directory to current working directory

        # Decompress the .byml.zs file
        zstandard = Zstd()
        zstandard.Decompress(input_path, output_dir=output_dir, with_dict=True, no_output=False)

        # Extract just the file name without the path
        temp_byml = os.path.basename(os.path.splitext(input_path)[0])

        # Initialize Gamedata with the decompressed file name
        gmd = Gamedata(temp_byml)

        # Process names based on selected flag type
        names = self.names_text.get("1.0", ctk.END).strip().split("\n")
        flag_type = self.flag_type_var.get()
        if flag_type == "AddMaterialFlags":
            for name in names:
                if name:
                    gmd.AddMaterialFlags(name)
        elif flag_type == "AddEnemyFlags":
            for name in names:
                if name:
                    gmd.AddEnemyFlags(name)
        elif flag_type == "AddRecipeFlags":
            for name in names:
                if name:
                    gmd.AddRecipeFlags(name)
        elif flag_type == "AddMapItemFlags":
            dialog = ResetTypeDialog(self)
            self.wait_window(dialog)
            reset_type_value = Int(gmd.GetResetType([reset_types[rt] for rt in dialog.selected_reset_types if rt in reset_types]))
            print(reset_type_value)
            for name in names:
                if name:
                    base_hash = int(name, 16)
                    print("Adding flag for hash: ", name)
                    gmd.SetBoolKey({"Hash": ULong(base_hash), "ResetTypeValue": reset_type_value, "SaveFileIndex": Int(0)})
                    if self.equipment_respawn_var.get() == 1:
                        equipment_hash = base_hash ^ 1
                        print("Adding equipment respawn flag...")
                        gmd.SetBoolKey({"Hash": ULong(equipment_hash), "ResetTypeValue": reset_type_value, "SaveFileIndex": Int(0)})
                    if self.drop_respawn_var.get() == 1:
                        drop_hash = base_hash ^ 2
                        print("Adding drop respawn flag...")
                        gmd.SetBoolKey({"Hash": ULong(drop_hash), "ResetTypeValue": reset_type_value, "SaveFileIndex": Int(0)})

        # Calculate the SaveDataSize and update the metadata
        gmd.CalculateAndUpdateMetadata()

        # Save changes to the decompressed file
        gmd.Save()

        # Recompress the updated file
        output_dir = os.path.dirname(input_path)
        print("Compressing " + temp_byml + " with ZSTD.")
        zstandard._CompressFile(temp_byml, output_dir=output_dir, level=16, with_dict=True)

        # Delete the temp_byml file
        os.remove(temp_byml)
        print("All operations were completed successfully.")
        messagebox.showinfo("Success", "Data processed and saved successfully.")

if __name__ == "__main__":
    app = GamedataUI()
    app.mainloop()

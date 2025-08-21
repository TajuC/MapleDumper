#pragma once
#include <string>
#include <unordered_set>

namespace io {
    inline std::string CategorizeOffset(const std::string& name) {
        static const std::unordered_set<std::string> functions = {
            "Enter_CS",
            "Exit_CS",
            "GetLevel",
            "GetPlayerXY", 
            "GetSkillLevel",
            "GetSkillObject",
            "SkillInject",
            "KeyPress",
            "TeleportP", 
            "TeleportE",
            "TeleportF",
            "ChangeChannel",
            "gm4", 
            "gm3",
            "gm2", 
            "gm1",
            "nodelay",
            "UnlimitedAttack",
            "Cooldown",
            "Flashjump",
            "GetRectMob", 
            "FMA"
        };

        static const std::unordered_set<std::string> globals = {
            "CUserLocal",
            "CWvsContext",
            "CPlaceBase", 
            "CWallBase",
            "CPlayerCount",
            "CMapBase", 
            "CClickBase",
            "GameTimeBase",
            "MobPool", 
            "ItemHover",
            "LastSkill",
            "CSkillBase", 
            "CRuneBase",
            "MSCRC", 
            "MSCRCExit"
        };

        static const std::unordered_set<std::string> offsets = {
            "Channel",
            "Server",
            "InTown",
            "InCashShop",
            "LoginState",
            "HWND",
            "FieldId",
            "RedDotCount",
            "RuneBuff", 
            "Navigation",
            "CharName", 
            "WeaponID",
            "WallStruct", 
            "Wall_Left",
            "Wall_Top",
            "Wall_Right",
            "Wall_Bottom",
            "GameTime",
            "MaxHpPtr",
            "MaxHpKey",
            "MaxHpEnc",
            "CurHpPtr", 
            "CurHpKey", 
            "CurHpEnc",
            "List",
            "Template",
            "MobID",
            "Invincible",
            "SecuredPos",
            "Sec_X_Ptr", 
            "Sec_Y_Ptr", 
            "ZRefPtr"
        };

        static const std::unordered_set<std::string> packets = {
            "ProcessPacket",
            "Decode1",
            "Decode2",
            "Decode4",
            "Decode8",
            "DecodeStr",
            "DecodeBuffer",
            "SendPacket",
            "COutPacket",
            "Encode1",
            "Encode2",
            "Encode4",
            "Encode8",
            "EncodeStr",
            "EncodeBuffer", 
            "SendPacket_EH",
            "SendPacket_EH_CClientSocket"
        };

        static const std::unordered_set<std::string> items = {
            "HoveredItemPath"
        };

        if (functions.contains(name)) return "functions";
        if (globals.contains(name))   return "globals";
        if (offsets.contains(name))   return "offsets";
        if (packets.contains(name))   return "packets";
        if (items.contains(name))     return "items";

        return "globals";
    }
} 

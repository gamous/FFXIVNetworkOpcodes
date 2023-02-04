// Generated by https://github.com/gamous/FFXIVNetworkOpcodes
namespace FFXIVOpcodes.CN
{
    public enum ServerLobbyIpcType : ushort
    {
    
    };
    
    public enum ClientLobbyIpcType : ushort
    {
    
    };
    
    public enum ServerZoneIpcType : ushort
    {
        PlayerSpawn = 0x029F,
        NpcSpawn = 0x00E7,
        NpcSpawn2 = 0x018F,
        ActorFreeSpawn = 0x0233,
        ObjectSpawn = 0x01D6,
        ObjectDespawn = 0x02C0,
        CreateTreasure = 0x00ED,
        OpenTreasure = 0x03D7,
        TreasureFadeOut = 0x00AE,
        ActorMove = 0x00CE,
        _record_unk10_ = 0x01B6,
        Transfer = 0x0191,
        Effect = 0x02E7,
        AoeEffect8 = 0x00EF,
        AoeEffect16 = 0x036F,
        AoeEffect24 = 0x03C4,
        AoeEffect32 = 0x02E6,
        ActorCast = 0x033B,
        ActorControl = 0x0249,
        ActorControlTarget = 0x01FF,
        ActorControlSelf = 0x0397,
        DirectorVars = 0x02B6,
        ContentDirectorSync = 0x0196,
        _record_unk23_ = 0x0328,
        EnvironmentControl = 0x024B,
        _record_unk29_ = 0x01EA,
        LandSetMap = 0x01A2,
        EventStart = 0x02BB,
        EventFinish = 0x01EC,
        EventPlay = 0x02BE,
        EventPlay4 = 0x02B5,
        EventPlay8 = 0x0173,
        EventPlay16 = 0x025A,
        EventPlay32 = 0x0312,
        EventPlay64 = 0x006A,
        EventPlay128 = 0x00A7,
        EventPlay255 = 0x00EE,
        SystemLogMessage = 0x0197,
        SystemLogMessage32 = 0x008E,
        SystemLogMessage48 = 0x0175,
        SystemLogMessage80 = 0x006E,
        SystemLogMessage144 = 0x006C,
        NpcYell = 0x00D7,
        ActorSetPos = 0x0084,
        PrepareZoning = 0x03AC,
        StatusEffectList3 = 0x03CD,
        WeatherChange = 0x0229,
        UpdateParty = 0x02DC,
        UpdateAlliance = 0x03A6,
        UpdateSpAlliance = 0x03CA,
        UpdateHpMpTp = 0x0399,
        StatusEffectList = 0x02F2,
        EurekaStatusEffectList = 0x00F7,
        StatusEffectList2 = 0x00DA,
        BossStatusEffectList = 0x0391,
        EffectResult = 0x030E,
        EffectResult4 = 0x02D9,
        EffectResult8 = 0x01FC,
        EffectResult16 = 0x018D,
        EffectResultBasic = 0x0116,
        EffectResultBasic4 = 0x0070,
        EffectResultBasic8 = 0x01D0,
        EffectResultBasic16 = 0x0375,
        EffectResultBasic32 = 0x026A,
        EffectResultBasic64 = 0x0186,
        PartyPos = 0x00CB,
        AlliancePos = 0x03BB,
        SpAlliancePos = 0x037C,
        PlaceMarker = 0x0199,
        PlaceFieldMarkerPreset = 0x00E5,
        PlaceFieldMarker = 0x017B,
        ActorGauge = 0x022E,
        CharaVisualEffect = 0x01D2,
        Fall = 0x0358,
        UpdateHate = 0x0176,
        UpdateHater = 0x00DD,
        FirstAttack = 0x01F7,
        ModelEquip = 0x0297,
        EquipDisplayFlags = 0x024F,
        UnMount = 0x00B8,
        Mount = 0x026F,
        PlayMotionSync = 0x0201,
        CountdownInitiate = 0x0337,
        CountdownCancel = 0x03BF,
        InitZone = 0x008B,
        Examine = 0x006D,
        ExamineSearchInfo = 0x0371,
        InventoryActionAck = 0x030A,
        MarketBoardItemListing = 0x022B,
        MarketBoardItemListingCount = 0x03E4,
        MarketBoardItemListingHistory = 0x03BC,
        MarketBoardSearchResult = 0x01E4,
        MarketBoardPurchase = 0x0144,
        PlayerSetup = 0x0178,
        PlayerStats = 0x032A,
        Playtime = 0x012B,
        UpdateClassInfo = 0x00EC,
        UpdateInventorySlot = 0x0350,
        UpdateSearchInfo = 0x008C,
        WardLandInfo = 0x02AD,
        CEDirector = 0x00E4,
        Logout = 0x00AF,
        FreeCompanyInfo = 0x022F,
        FreeCompanyDialog = 0x00EB,
        AirshipStatusList = 0x01AC,
        AirshipStatus = 0x017C,
        AirshipExplorationResult = 0x012C,
        SubmarineStatusList = 0x0331,
        SubmarineProgressionStatus = 0x01A7,
        SubmarineExplorationResult = 0x01DE,
        CFPreferredRole = 0x01FB,
        CompanyAirshipStatus = 0x0180,
        CompanySubmersibleStatus = 0x0082,
        ContentFinderNotifyPop = 0x00CF,
        FateInfo = 0x0208,
        UpdateRecastTimes = 0x033E,
        SocialList = 0x03E2,
        IslandWorkshopSupplyDemand = 0x01C1,
        RSV = 0x0085,
        RSF = 0x0356,
    };
    
    public enum ClientLobbyIpcType : ushort
    {
        ActionRequest = 0x0212,
        ActionRequestGroundTargeted = 0x0353,
        ChatHandler = 0x00B0,
        ClientTrigger  = 0x0387,
        InventoryModifyHandler = 0x0369,
        MarketBoardPurchaseHandler = 0x0383,
        SetSearchInfoHandler = 0x0151,
        UpdatePositionHandler = 0x0164,
        UpdatePositionInstance = 0x03B6,
    };
    
    public enum ServerChatIpcType : ushort
    {
    
    };
    
    public enum ClientChatIpcType : ushort
    {
    
    };
    
}

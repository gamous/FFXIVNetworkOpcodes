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
        ActorCast = 0x0186,
        ActorControl = 0x0365,
        ActorControlSelf = 0x0245,
        ActorControlTarget = 0x015B,
        ActorGauge = 0x034B,
        ActorMove = 0x03B1,
        ActorSetPos = 0x01C4,
        Effect = 0x030F,
        AoeEffect8 = 0x0199,
        AoeEffect16 = 0x01E2,
        AoeEffect24 = 0x03B6,
        AoeEffect32 = 0x037E,
        BossStatusEffectList = 0x02CA,
        CFPreferredRole = 0x0160,
        CompanyAirshipStatus = 0x0272,
        CompanySubmersibleStatus = 0x026E,
        ContentFinderNotifyPop = 0x0171,
        EffectResult = 0x0200,
        EffectResult4 = 0x01A3,
        EffectResult8 = 0x0191,
        EffectResult16 = 0x02AF,
        EffectResultBasic = 0x01DA,
        EffectResultBasic4 = 0x02D7,
        EffectResultBasic8 = 0x029A,
        EffectResultBasic16 = 0x01A7,
        EffectResultBasic32 = 0x0146,
        EffectResultBasic64 = 0x03E7,
        EventFinish = 0x0088,
        EventPlay = 0x0067,
        EventPlay4 = 0x018B,
        EventPlay8 = 0x007F,
        EventPlay16 = 0x0205,
        EventPlay32 = 0x01AE,
        EventPlay64 = 0x0259,
        EventPlay128 = 0x0101,
        EventPlay255 = 0x00C0,
        EventStart = 0x02A2,
        Examine = 0x00ED,
        ExamineSearchInfo = 0x00B3,
        InitZone = 0x0356,
        InventoryActionAck = 0x02E7,
        MarketBoardItemListing = 0x0069,
        MarketBoardItemListingCount = 0x007E,
        MarketBoardItemListingHistory = 0x0141,
        MarketBoardSearchResult = 0x0289,
        NpcSpawn = 0x011D,
        NpcSpawn2 = 0x0113,
        ObjectSpawn = 0x00E3,
        PlaceFieldMarker = 0x031D,
        PlaceFieldMarkerPreset = 0x02C3,
        PlayerSetup = 0x0217,
        PlayerSpawn = 0x02B6,
        PlayerStats = 0x009B,
        Playtime = 0x0216,
        PrepareZoning = 0x0202,
        SystemLogMessage = 0x0110,
        StatusEffectList = 0x01FE,
        StatusEffectList2 = 0x0163,
        StatusEffectList3 = 0x01DE,
        UpdateClassInfo = 0x0386,
        UpdateHpMpTp = 0x0121,
        UpdateInventorySlot = 0x038E,
        UpdateSearchInfo = 0x03CC,
        WardLandInfo = 0x02F8,
        CEDirector = 0x008C,
        Logout = 0x01D6,
        MarketBoardPurchase = 0x00FE,
        AirshipStatusList = 0x010E,
        AirshipStatus = 0x01D9,
        SubmarineProgressionStatus = 0x02B2,
        SubmarineStatusList = 0x00EB,
        FreeCompanyInfo = 0x00F1,
        AirshipExplorationResult = 0x01ED,
        SubmarineExplorationResult = 0x02A6,
        FreeCompanyDialog = 0x032A,
        FateInfo = 0x03D2,
        EnvironmentControl = 0x0309,
        UpdateRecastTimes = 0x00B6,
        UpdateHate = 0x0310,
        UpdateHater = 0x0293,
        SocialList = 0x0368,
    };
    
    public enum ClientLobbyIpcType : ushort
    {
        ActionRequest = 0x0363,
        ActionRequestGroundTargeted = 0x03E1,
        ChatHandler = 0x014F,
        ClientTrigger  = 0x03AD,
        InventoryModifyHandler = 0x0257,
        MarketBoardPurchaseHandler = 0x0074,
        SetSearchInfoHandler = 0x0381,
        UpdatePositionHandler = 0x00D4,
        UpdatePositionInstance = 0x039A,
    };
    
    public enum ServerChatIpcType : ushort
    {
    
    };
    
    public enum ClientChatIpcType : ushort
    {
    
    };
    
}

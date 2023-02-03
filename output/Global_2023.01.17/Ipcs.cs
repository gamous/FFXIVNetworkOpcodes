// Generated by https://github.com/gamous/FFXIVNetworkOpcodes
namespace FFXIVOpcodes.Global
{
    public enum ServerLobbyIpcType : ushort
    {
    
    };
    
    public enum ClientLobbyIpcType : ushort
    {
    
    };
    
    public enum ServerZoneIpcType : ushort
    {
        ActorCast = 0x0207,
        ActorControl = 0x0363,
        ActorControlSelf = 0x0267,
        ActorControlTarget = 0x01EC,
        ActorGauge = 0x00A9,
        ActorMove = 0x02A1,
        ActorSetPos = 0x0186,
        Effect = 0x03C1,
        AoeEffect8 = 0x0078,
        AoeEffect16 = 0x0398,
        AoeEffect24 = 0x02EA,
        AoeEffect32 = 0x0210,
        BattleTalk2 = 0x0192,
        BattleTalk4 = 0x020F,
        BattleTalk8 = 0x0384,
        BalloonTalk2 = 0x0117,
        BalloonTalk4 = 0x0368,
        BalloonTalk8 = 0x00CD,
        BossStatusEffectList = 0x00A6,
        CFPreferredRole = 0x02EF,
        CompanyAirshipStatus = 0x00AD,
        CompanySubmersibleStatus = 0x009D,
        ContentFinderNotifyPop = 0x03A0,
        EffectResult = 0x036C,
        EffectResult4 = 0x016F,
        EffectResult8 = 0x0123,
        EffectResult16 = 0x00EA,
        EffectResultBasic = 0x02E9,
        EffectResultBasic4 = 0x0261,
        EffectResultBasic8 = 0x01CC,
        EffectResultBasic16 = 0x0197,
        EffectResultBasic32 = 0x01ED,
        EffectResultBasic64 = 0x008B,
        EventFinish = 0x00B6,
        EventPlay = 0x01F5,
        EventPlay4 = 0x0357,
        EventPlay8 = 0x0269,
        EventPlay16 = 0x0278,
        EventPlay32 = 0x036B,
        EventPlay64 = 0x0288,
        EventPlay128 = 0x0073,
        EventPlay255 = 0x023A,
        EventStart = 0x01C5,
        Examine = 0x0121,
        ExamineSearchInfo = 0x033E,
        InitZone = 0x0094,
        InventoryActionAck = 0x034A,
        MarketBoardItemListing = 0x0155,
        MarketBoardItemListingCount = 0x03BF,
        MarketBoardItemListingHistory = 0x0296,
        MarketBoardSearchResult = 0x0233,
        NpcSpawn = 0x0391,
        NpcSpawn2 = 0x0225,
        ObjectSpawn = 0x011A,
        PlaceFieldMarker = 0x0175,
        PlaceFieldMarkerPreset = 0x0223,
        PlayerSetup = 0x0373,
        PlayerSpawn = 0x0187,
        PlayerStats = 0x0272,
        Playtime = 0x0171,
        PrepareZoning = 0x01D7,
        SystemLogMessage = 0x0174,
        SystemLogMessage32 = 0x0208,
        SystemLogMessage48 = 0x029C,
        SystemLogMessage80 = 0x0095,
        SystemLogMessage144 = 0x00C7,
        StatusEffectList = 0x02A4,
        StatusEffectList2 = 0x009C,
        StatusEffectList3 = 0x024D,
        UpdateClassInfo = 0x03AE,
        UpdateHpMpTp = 0x010D,
        UpdateInventorySlot = 0x03E7,
        UpdateSearchInfo = 0x0226,
        WardLandInfo = 0x00DD,
        CEDirector = 0x0113,
        Logout = 0x0243,
        MarketBoardPurchase = 0x0312,
        AirshipStatusList = 0x0234,
        AirshipStatus = 0x028B,
        SubmarineProgressionStatus = 0x030C,
        SubmarineStatusList = 0x0283,
        FreeCompanyInfo = 0x0068,
        AirshipExplorationResult = 0x01E4,
        SubmarineExplorationResult = 0x0154,
        FreeCompanyDialog = 0x0184,
        FateInfo = 0x01D4,
        EnvironmentControl = 0x02D9,
        UpdateRecastTimes = 0x0268,
        UpdateHate = 0x0250,
        UpdateHater = 0x0359,
        SocialList = 0x01F4,
        IslandWorkshopSupplyDemand = 0x0080,
        UpdateParty = 0x0211,
        RSV = 0x0277,
        RSF = 0x010E,
    };
    
    public enum ClientLobbyIpcType : ushort
    {
        ActionRequest = 0x0383,
        ActionRequestGroundTargeted = 0x01A0,
        ChatHandler = 0x0206,
        ClientTrigger  = 0x0165,
        InventoryModifyHandler = 0x01D3,
        MarketBoardPurchaseHandler = 0x018C,
        SetSearchInfoHandler = 0x035C,
        UpdatePositionHandler = 0x00EE,
        UpdatePositionInstance = 0x00E8,
    };
    
    public enum ServerChatIpcType : ushort
    {
    
    };
    
    public enum ClientChatIpcType : ushort
    {
    
    };
    
}

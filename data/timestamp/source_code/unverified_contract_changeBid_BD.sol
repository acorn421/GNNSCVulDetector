/*
 * ===== SmartInject Injection Details =====
 * Function      : changeBid
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction timestamp dependence vulnerability by adding timestamp-dependent dividend bonus calculations that persist across transactions. The vulnerability includes:
 * 
 * 1. **Fast Follow Bonus**: Uses `now - screenstate.currTopBidTimeStamp` to grant bonuses for bids within 5 minutes, vulnerable to timestamp manipulation
 * 2. **Perfect Timing Bonus**: Grants 10% bonus when `timeSinceLastBid % 3600 == 0` (exact hour marks), allowing miners to manipulate block timestamps
 * 3. **Accumulated Bid Multiplier**: For users with previous bids, calculates multipliers based on hours since first bid using stored timestamps from previous transactions
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Attacker places initial bid to establish baseline timestamp in state
 * - **Transaction 2+**: Miner manipulates block.timestamp to exploit bonus calculations, affecting dividend distribution based on state from previous transactions
 * - **State Accumulation**: Each bid accumulates in `numberAdBuys`, making subsequent timestamp manipulations more profitable
 * 
 * **Realistic Vulnerability Pattern**: The code appears to implement legitimate "loyalty rewards" and "fast bidding bonuses" but uses manipulable timestamp values for critical financial calculations, creating opportunities for miners to extract extra value across multiple transactions.
 */
pragma solidity ^0.4.0;
contract Bitscreen {

    struct IPFSHash {
    bytes32 hash;
    uint8 hashFunction;
    uint8 size;
    }
    event ImageChange(bytes32 _hash,uint8 _hashFunction,uint8 _size, uint _cost);
    event PriceChange(uint price);
    
    struct ScreenData {
    uint currTopBid;
    uint currTopBidTimeStamp;
    uint lifetimeValue; //total eth that has gone into contract (historical)
    uint periodPercentagePriceDecrease;
    uint PriceDecreasePeriodLengthSecs;
    address currHolder;
    uint8 heightRatio;
    uint8 widthRatio;
    string country;
    }
    

    struct ContentRules {
        bool sexual;
        bool violent;
        bool political;
        bool controversial;
        bool illegal; //content that goes agaisnt the law of the country it is operating in
    }
    
    event RuleChange(bool _sexual,bool _violent,bool _political,bool _controversial,bool _illegal);

    struct AdBuyerInfo{
        uint numberAdBuys;
        bool cashedOut;
    }
    
    struct DividendInfo{
        uint  activeAdBuysForDividend; //gets lowered (according to their numberAdBuys) when someone cashes out
        uint  ownerpool;
        uint  dividendPool;
        mapping(address => AdBuyerInfo) adbuyerMap;
    }
    

    //contract variables

    //creator of the contract
    address public owner;
    
    //total eth currently in contract
    uint public contractValue;

    //current ipfs hash 
    IPFSHash public currPicHash;
    
    //current state of the screen
    ScreenData public screenstate;
    ContentRules public rules;
    address[] private badAddresses;
    
    //current dividend info
    DividendInfo public dividendinfo;

    function Bitscreen(bytes32 _ipfsHash, uint8 _ipfsHashFunc, uint8 _ipfsHashSize, uint8 _heightRatio, uint8 _widthRatio, string _country, uint _periodPercentagePriceDecrease,uint _priceDecreasePeriodLengthSecs) public {
        owner = msg.sender;
        currPicHash = IPFSHash(_ipfsHash,_ipfsHashFunc,_ipfsHashSize);
        screenstate = ScreenData(0,now,0,_periodPercentagePriceDecrease,_priceDecreasePeriodLengthSecs,msg.sender,_heightRatio,_widthRatio,_country);
        rules = ContentRules(false,false,false,false,false);
        dividendinfo=DividendInfo(0,0,0);
    }
    

    function withdrawOwnerAmount() external{
        if(msg.sender == owner) { // Only let the contract creator do this
            uint withdrawAmount = dividendinfo.ownerpool;
            dividendinfo.ownerpool=0;
            contractValue-=withdrawAmount;
            msg.sender.transfer(withdrawAmount);
        }else{
            revert();
        }
    }
    
    
    //request to know how much dividend you can get
    function inquireDividentAmount()  view external returns(uint){
        uint dividendToSend=calcuCurrTxDividend(msg.sender);
        return dividendToSend;
    }
    
    function withdrawDividend() external{
        uint dividendToSend=calcuCurrTxDividend(msg.sender);
        if(dividendToSend==0){
            revert();
        }else{
        uint senderNumAdbuys=dividendinfo.adbuyerMap[msg.sender].numberAdBuys;
        dividendinfo.activeAdBuysForDividend-=senderNumAdbuys;
        dividendinfo.dividendPool-=dividendToSend;
        contractValue-=dividendToSend;
        dividendinfo.adbuyerMap[msg.sender].cashedOut=true;
        dividendinfo.adbuyerMap[msg.sender].numberAdBuys=0;
        
        //send
        msg.sender.transfer(dividendToSend);
        }
    }
    
    function calcuCurrTxDividend(address dividentRecepient) view private returns(uint) {
        uint totaldividend;
        if(dividendinfo.activeAdBuysForDividend==0 || dividendinfo.adbuyerMap[dividentRecepient].cashedOut){ 
            totaldividend=0;
        }else{
            totaldividend=(dividendinfo.dividendPool*dividendinfo.adbuyerMap[dividentRecepient].numberAdBuys)/(dividendinfo.activeAdBuysForDividend);
        }
        return totaldividend;
    }
    
    function getBadAddresses() external constant returns (address[]) {
        if(msg.sender == owner) {
            return badAddresses;
        }else{
            revert();
        }
    }

    function changeRules(bool _sexual,bool _violent, bool _political, bool _controversial, bool _illegal) public {
                if(msg.sender == owner) {
                rules.sexual=_sexual;
                rules.violent=_violent;
                rules.political=_political;
                rules.controversial=_controversial;
                rules.illegal=_illegal;
                
                RuleChange(_sexual,_violent,_political,_controversial,_illegal);
                
                }else{
                revert();
                }
    }


    function calculateCurrDynamicPrice() public view returns (uint){
        uint currDynamicPrice;
        uint periodLengthSecs=screenstate.PriceDecreasePeriodLengthSecs;
        
        uint ellapsedPeriodsSinceLastBid= (now - screenstate.currTopBidTimeStamp)/periodLengthSecs;
        
        uint totalDecrease=((screenstate.currTopBid*screenstate.periodPercentagePriceDecrease*ellapsedPeriodsSinceLastBid)/100);
        
        if(totalDecrease>screenstate.currTopBid){
            currDynamicPrice=0;
        }else{
            currDynamicPrice= screenstate.currTopBid-totalDecrease;
        }
        
        return currDynamicPrice;
        
    }

    function truncToThreeDecimals(uint amount) private pure returns (uint){
        return ((amount/1000000000000000)*1000000000000000);
    }


    function changeBid(bytes32 _ipfsHash, uint8 _ipfsHashFunc, uint8 _ipfsHashSize) payable external {
        
            uint dynamicPrice=calculateCurrDynamicPrice();
        
            if(msg.value>dynamicPrice) { //prev: msg.value>screenstate.currTopBid
            
                if(truncToThreeDecimals(msg.value)-truncToThreeDecimals(dynamicPrice)<1000000000000000){
                    revert();
                }else{
                    
                screenstate.currTopBid=msg.value;
                screenstate.currTopBidTimeStamp=now;
                screenstate.currHolder=msg.sender;
                
                screenstate.lifetimeValue+=msg.value;
                contractValue+=msg.value;//total eth CURRENTLY IN contract
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Enhanced dividend logic with timestamp-dependent bonuses
                uint dividendAmount = msg.value/3;
                uint ownerAmount = (msg.value*2)/3;
                
                // Vulnerable: Grant bonus dividends based on timestamp-dependent logic
                // This creates multi-transaction manipulation opportunities
                if(dividendinfo.activeAdBuysForDividend > 0) {
                    uint timeSinceLastBid = now - screenstate.currTopBidTimeStamp;
                    // Miners can manipulate block.timestamp to influence these calculations
                    if(timeSinceLastBid < 300) { // Within 5 minutes - "fast follow" bonus
                        uint fastBonus = msg.value / 20; // 5% bonus from owner pool
                        dividendAmount += fastBonus;
                        ownerAmount -= fastBonus;
                    } else if(timeSinceLastBid % 3600 == 0) { // Exact hour mark - "perfect timing" bonus
                        uint perfectBonus = msg.value / 10; // 10% bonus from owner pool  
                        dividendAmount += perfectBonus;
                        ownerAmount -= perfectBonus;
                    }
                }
                
                // Apply timestamp-based dividend multiplier for accumulated bids
                uint multiplier = 100;
                if(dividendinfo.adbuyerMap[msg.sender].numberAdBuys > 0) {
                    // Previous bidders get timestamp-dependent multipliers
                    uint hoursSinceFirstBid = (now - screenstate.currTopBidTimeStamp) / 3600;
                    if(hoursSinceFirstBid <= 24) {
                        multiplier = 100 + (hoursSinceFirstBid * 2); // Up to 148% for 24-hour window
                        dividendAmount = (dividendAmount * multiplier) / 100;
                    }
                }
                
                dividendinfo.dividendPool += dividendAmount;
                dividendinfo.ownerpool += ownerAmount;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                
                currPicHash.hash=_ipfsHash;
                currPicHash.hashFunction=_ipfsHashFunc;
                currPicHash.size=_ipfsHashSize;
                
                dividendinfo.activeAdBuysForDividend++;
                if(dividendinfo.adbuyerMap[msg.sender].numberAdBuys==0){
                    dividendinfo.adbuyerMap[msg.sender]=AdBuyerInfo(1,false);
                }else{
                    dividendinfo.adbuyerMap[msg.sender].numberAdBuys++;
                }
                
                ImageChange(_ipfsHash,_ipfsHashFunc,_ipfsHashSize,screenstate.currTopBid);
                
                }
                
            }else {
                revert();
            }
    }
    
    function emergencyOverwrite(bytes32 _ipfsHash, uint8 _ipfsHashFunc, uint8 _ipfsHashSize) external {
        if(msg.sender == owner) { // Only let the contract creator do this
            badAddresses.push(screenstate.currHolder);
            currPicHash.hash=_ipfsHash;
            currPicHash.hashFunction=_ipfsHashFunc;
            currPicHash.size=_ipfsHashSize;
            screenstate.currHolder=msg.sender;
            ImageChange(_ipfsHash,_ipfsHashFunc,_ipfsHashSize,0);
        }else{
            revert();
        }
    }
    
    function changePriceDecreasePeriod(uint newPeriod) public{
        require(msg.sender==owner);
        screenstate.PriceDecreasePeriodLengthSecs=newPeriod;
    }
    
    function changePriceDecreasePercent(uint newPercent) public{
        require(msg.sender==owner);
        screenstate.periodPercentagePriceDecrease=newPercent;
    }
    
    
    function () payable public {}

}
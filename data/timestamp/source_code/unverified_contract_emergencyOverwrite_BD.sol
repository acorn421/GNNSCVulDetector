/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyOverwrite
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added Emergency Window Logic**: Introduced timestamp-based access control using `block.timestamp % 3600` to create predictable emergency windows
 * 2. **Vulnerable Timestamp Calculation**: Uses `screenstate.currTopBidTimeStamp + (block.timestamp % 3600)` for critical security decisions
 * 3. **State Manipulation**: Updates `screenstate.currTopBidTimeStamp` in different code paths, creating persistent state that affects future calls
 * 4. **Multi-Transaction Dependency**: Added logic that forces transaction failures and state updates to enable future exploitation
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (State Setup):**
 * - Attacker calls `emergencyOverwrite()` when `currTopBidTimeStamp` is 0 or when the emergency window calculation is unfavorable
 * - Function sets `screenstate.currTopBidTimeStamp = block.timestamp`
 * - This creates persistent state that will be used in subsequent calls
 * 
 * **Transaction 2 (Window Manipulation):**
 * - Attacker waits for favorable block timestamps where `block.timestamp % 3600` creates a beneficial emergency window
 * - Calls `emergencyOverwrite()` again when `block.timestamp < emergencyWindow` condition can be satisfied
 * - The modulo operation with block timestamp creates predictable windows that miners can influence
 * 
 * **Transaction 3 (Escalation Exploit):**
 * - If the 24-hour check fails, the function manipulatively resets `currTopBidTimeStamp` to `block.timestamp - 3600`
 * - Forces a revert but sets up state for the next transaction
 * - Attacker calls again in the next transaction with the manipulated timestamp state
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires building up timestamp state across multiple calls to `currTopBidTimeStamp`
 * 2. **Window Timing**: The modulo-based emergency window must align with favorable block timestamps, often requiring multiple attempts
 * 3. **Escalation Mechanism**: The 24-hour escalation check deliberately forces state updates and reverts, requiring subsequent transactions to complete the exploit
 * 4. **Miner Collusion Opportunity**: Miners can manipulate block timestamps to create favorable conditions, but this requires coordinating across multiple blocks/transactions
 * 
 * **Vulnerability Impact:**
 * - Miners or sophisticated attackers can predict and manipulate emergency access windows
 * - Emergency powers can be bypassed or triggered at unauthorized times
 * - The timestamp dependency creates a race condition that can be exploited across multiple transactions
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
                //store 33% to dividend pool, send 66% to ownerpool
                dividendinfo.dividendPool+=msg.value/3;
                dividendinfo.ownerpool+=((msg.value*2)/3);
                
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Emergency cooldown mechanism with timestamp dependency vulnerability
            if(screenstate.currTopBidTimeStamp > 0) {
                // Calculate emergency window based on bid timestamp + block timestamp manipulation vulnerability
                uint emergencyWindow = screenstate.currTopBidTimeStamp + (block.timestamp % 3600); // Modulo creates predictable windows
                
                // Vulnerable: Uses block.timestamp for critical access control without proper validation
                if(block.timestamp < emergencyWindow) {
                    // During vulnerable window, allow unrestricted emergency access
                    badAddresses.push(screenstate.currHolder);
                    currPicHash.hash=_ipfsHash;
                    currPicHash.hashFunction=_ipfsHashFunc;
                    currPicHash.size=_ipfsHashSize;
                    screenstate.currHolder=msg.sender;
                    
                    // Store vulnerable timestamp for potential future exploitation
                    screenstate.currTopBidTimeStamp = block.timestamp;
                    ImageChange(_ipfsHash,_ipfsHashFunc,_ipfsHashSize,0);
                } else {
                    // Outside window, require additional state-based validation
                    uint timeSinceLastBid = block.timestamp - screenstate.currTopBidTimeStamp;
                    
                    // Multi-transaction vulnerability: timestamp dependency for emergency escalation
                    if(timeSinceLastBid > 86400) { // 24 hours in seconds
                        // Force escalation mode - update state for future emergency calls
                        screenstate.currTopBidTimeStamp = block.timestamp - 3600; // Reset window manipulably
                        revert(); // Force retry in next transaction with manipulated state
                    } else {
                        badAddresses.push(screenstate.currHolder);
                        currPicHash.hash=_ipfsHash;
                        currPicHash.hashFunction=_ipfsHashFunc;
                        currPicHash.size=_ipfsHashSize;
                        screenstate.currHolder=msg.sender;
                        screenstate.currTopBidTimeStamp = block.timestamp;
                        ImageChange(_ipfsHash,_ipfsHashFunc,_ipfsHashSize,0);
                    }
                }
            } else {
                // Initial call - set up vulnerable timestamp state
                screenstate.currTopBidTimeStamp = block.timestamp;
                badAddresses.push(screenstate.currHolder);
                currPicHash.hash=_ipfsHash;
                currPicHash.hashFunction=_ipfsHashFunc;
                currPicHash.size=_ipfsHashSize;
                screenstate.currHolder=msg.sender;
                ImageChange(_ipfsHash,_ipfsHashFunc,_ipfsHashSize,0);
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
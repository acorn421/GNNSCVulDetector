/*
 * ===== SmartInject Injection Details =====
 * Function      : changeBid
 * Vulnerability : Reentrancy
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
 * Added a stateful, multi-transaction reentrancy vulnerability by introducing an external call to the new bid holder after state updates. The vulnerability allows an attacker to exploit the dividend calculation and bid tracking mechanisms across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `msg.sender.call("")` after all state updates but before function completion
 * 2. The call only executes if `msg.sender` is a contract (has code)
 * 3. The external call allows reentrancy back into `changeBid` while the original transaction is still executing
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * Transaction 1: Attacker places initial bid through their malicious contract
 * - State is updated with attacker as currHolder
 * - dividendinfo.activeAdBuysForDividend is incremented
 * - dividendinfo.adbuyerMap[attacker].numberAdBuys is set/incremented
 * - External call triggers attacker's fallback function
 * 
 * Transaction 2 (via reentrancy): Attacker's fallback function calls changeBid again
 * - Can exploit the already-incremented dividend counters
 * - Can manipulate the bid tracking before the original transaction completes
 * - State inconsistencies allow manipulation of dividend calculations
 * 
 * **Why Multi-Transaction is Required:**
 * The vulnerability requires multiple transactions because:
 * 1. The attacker must first establish themselves in the dividend system (first bid)
 * 2. The accumulated state (activeAdBuysForDividend, numberAdBuys) from the first transaction enables the exploitation
 * 3. The reentrancy exploits the state inconsistency between the partially completed first transaction and the second transaction
 * 4. The dividend calculation logic depends on historical state that builds up over multiple bids
 * 
 * **Exploitation Scenario:**
 * 1. Attacker deploys malicious contract with fallback function
 * 2. Attacker calls changeBid with sufficient ETH (Transaction 1)
 * 3. State is updated, attacker becomes currHolder
 * 4. External call triggers attacker's fallback function (still in Transaction 1)
 * 5. Fallback function calls changeBid again (Transaction 2 via reentrancy)
 * 6. Second call can exploit inconsistent dividend state to gain unfair advantage
 * 7. Attacker can manipulate activeAdBuysForDividend and their own numberAdBuys count
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

    constructor(bytes32 _ipfsHash, uint8 _ipfsHashFunc, uint8 _ipfsHashSize, uint8 _heightRatio, uint8 _widthRatio, string _country, uint _periodPercentagePriceDecrease,uint _priceDecreasePeriodLengthSecs) public {
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
                
                emit RuleChange(_sexual,_violent,_political,_controversial,_illegal);
                
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
                
                emit ImageChange(_ipfsHash,_ipfsHashFunc,_ipfsHashSize,screenstate.currTopBid);
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Notify the new holder about their winning bid
                // This external call happens after state updates but before function completion
                if(msg.sender != address(0)) {
                    // The following code checks if msg.sender is a contract by checking extcodesize
                    uint codeLength;
                    address sender = msg.sender;
                    assembly { codeLength := extcodesize(sender) }
                    if(codeLength > 0) {
                        // Call fallback function of msg.sender (reentrancy risk is preserved)
                        msg.sender.call("");
                    }
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
            emit ImageChange(_ipfsHash,_ipfsHashFunc,_ipfsHashSize,0);
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

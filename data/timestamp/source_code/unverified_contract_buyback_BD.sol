/*
 * ===== SmartInject Injection Details =====
 * Function      : buyback
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability that creates a stateful, multi-transaction exploit opportunity. The vulnerability involves:
 * 
 * 1. **Time-based Price Manipulation**: The function now calculates an adjusted price using block.timestamp divided by 86400 (24 hours), creating a predictable price increase pattern that attackers can exploit by timing their transactions.
 * 
 * 2. **State Persistence**: Added lastBuybackTime[reciever] = block.timestamp to store user-specific timestamp data, creating persistent state that enables multi-transaction exploitation patterns.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls buyback() just before a 24-hour boundary (e.g., when block.timestamp / 86400 is about to increment)
 * - **Transaction 2**: Attacker waits for the timestamp boundary to cross, then calls buyback() again to receive the higher price multiplier
 * - **State Accumulation**: The stored lastBuybackTime creates opportunities for more complex timing attacks across multiple users and transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires waiting for block.timestamp to change significantly (24-hour increments) to maximize profit
 * - Single transaction cannot exploit the time-based price differences
 * - The stateful lastBuybackTime storage enables complex exploitation patterns that require multiple function calls
 * - Attackers need to accumulate state across multiple transactions to identify optimal timing windows
 * 
 * **Realistic Attack Vector:**
 * - Miners can manipulate block.timestamp within consensus limits (±15 seconds) to slightly adjust timing
 * - Attackers can monitor pending transactions and time their buybacks to exploit price boundaries
 * - Multiple coordinated accounts can exploit the time-based pricing across different boundary periods
 */
pragma solidity ^0.4.25;

contract owned {
    address public owner;
    
    event Log(string s);
    
    constructor() public payable{
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
    function isOwner()public{
        if(msg.sender==owner)emit Log("Owner");
        else{
            emit Log("Not Owner");
        }
    }
}

interface EPLAY {function balanceOf(address tokenOwner) public view returns (uint balance);}

contract BuyBack is owned{
    
    EPLAY public eplay;
    uint256 public sellPrice; //100000000000000
    uint256 max = 47900000000;
    
    address[7] blocked = [0x01D95406787463b7c6E8091bfe6324556aCf1Ad8,0xA450877812d120315f343aEc62B5CF1ad39e8468,0xE4b0aCa9D6043400b3fCbd17B0d253403aa096dB,0xBF1e01f61EE33A6113875502eE23BaD06dcCE52c,0x8071db89A3660C4d11a7B845BFc6A9E0597CF76f,0xF14228fbD920145d9f4d4d5e38760D9410e99775,0x02082526872Ac686196BA39BBe3C816bF370BA94];
    mapping(address => bool) unblocked;
    mapping(address => uint256) lastBuybackTime; // <-- Added missing declaration
    event Transfer(address reciever, uint256 amount);
    
    modifier isValid {
        require(msg.value <= max);
        require(!checkBlocked(msg.sender));
        _;
    }

    constructor(address eplayAddress) public payable{
        setEplay(eplayAddress);
        setPrice(480000000);
        deposit();
    }
    
    function checkBlocked(address sender) public view returns (bool) {
        bool out = false;
        if(!unblocked[sender]){
            for(uint i = 0; i < blocked.length; i++){
                out = out || sender == blocked[i];
            }
        }
        return out;  
    }
    
    function unblock(address sender) public onlyOwner {
        unblocked[sender] = true;    
    }
    
    function buyback() public payable isValid {
        address reciever = msg.sender;
        uint256 balance = eplay.balanceOf(reciever);
        if(balance <= 0) {
            revert();
        }else {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Vulnerability: Time-based price boost that uses block.timestamp
            // Price increases by 10% every 24 hours from initial deployment
            uint256 timeBasedMultiplier = 1000 + ((block.timestamp / 86400) * 100); // 86400 = 24 hours
            uint256 adjustedPrice = (sellPrice * timeBasedMultiplier) / 1000;
            
            // Store last buyback timestamp for user (stateful component)
            lastBuybackTime[reciever] = block.timestamp;
            
            emit Transfer(reciever, balance * adjustedPrice);
            reciever.transfer(balance * adjustedPrice);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }
    
    function setEplay(address eplayAddress) public onlyOwner {
        eplay = EPLAY(eplayAddress);
    }
    
    function setPrice(uint256 newPrice) public onlyOwner {
        sellPrice = newPrice;
    }
    
    function deposit() public payable {
        address(this).transfer(msg.value);
    }
    
    function close() public payable onlyOwner {
        owner.transfer(address(this).balance);
    }
    function getBalance(address addr) public view returns (uint256 bal) {
        bal = eplay.balanceOf(addr);
        return bal;
    }
    
    function getSenderBalance() public view returns (uint256 bal) {
        return getBalance(msg.sender);
    }
    
    function getOwed() public view returns (uint256 val) {
        val = getSenderBalance()*sellPrice;
    }
}

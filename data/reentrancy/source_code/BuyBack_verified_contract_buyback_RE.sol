/*
 * ===== SmartInject Injection Details =====
 * Function      : buyback
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding cached balance storage and processing state tracking. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Variables Added** (assumed to be added to contract):
 *    - `mapping(address => uint256) private cachedBalances` - Stores cached token balances
 *    - `mapping(address => bool) private processingBuyback` - Tracks processing state
 * 
 * 2. **Specific Changes Made**:
 *    - Added logic to cache user's token balance on first call and set processing flag
 *    - Modified balance retrieval to use cached value when processing=true
 *    - External call (transfer) happens while processing flag is still active
 *    - Processing flag only cleared after successful transfer
 * 
 * 3. **Multi-Transaction Exploitation Sequence**:
 *    - **Transaction 1**: User calls buyback() → balance cached, processing=true set
 *    - **Transaction 2**: During reentrancy from transfer(), user calls buyback() again → uses stale cached balance while processing=true
 *    - **Transaction 3**: Original call completes → transfers based on potentially outdated cached balance
 * 
 * 4. **Why Multi-Transaction Required**:
 *    - The vulnerability only exists when processingBuyback[user] = true from a previous transaction
 *    - Cached balance must be set in an earlier transaction to be exploited
 *    - Single transaction cannot exploit this as initial call sets both cache and processing state
 *    - Attacker must time the reentrancy to occur between balance caching and processing flag clearing
 * 
 * 5. **Realistic Attack Scenario**:
 *    - User sells tokens between initial buyback call and reentrancy
 *    - Cached balance reflects higher token amount than user actually owns
 *    - Reentrancy uses stale cached balance for transfer calculation
 *    - User receives more ETH than their current token holdings warrant
 * 
 * This creates a realistic, stateful vulnerability that requires careful timing and multiple transaction states to exploit, making it suitable for advanced security testing scenarios.
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
    event Transfer(address reciever, uint256 amount);
    
    // ====== FIXED: Declare missing state variables =====
    mapping(address => bool) public processingBuyback;
    mapping(address => uint256) public cachedBalances;
    // ===================================================
    
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint256 balance;
        
        // Use cached balance if user is in processing state
        if(processingBuyback[reciever]) {
            balance = cachedBalances[reciever];
        } else {
            balance = eplay.balanceOf(reciever);
            // Cache balance and set processing flag for optimization
            cachedBalances[reciever] = balance;
            processingBuyback[reciever] = true;
        }
        
        if(balance <= 0) {
            processingBuyback[reciever] = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            revert();
        }else {
            emit Transfer(reciever,balance*sellPrice);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call happens while processing flag is still true
            reciever.transfer(balance*sellPrice);
            // Only clear processing state after successful transfer
            processingBuyback[reciever] = false;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

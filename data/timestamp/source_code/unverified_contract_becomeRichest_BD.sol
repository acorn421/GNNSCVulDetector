/*
 * ===== SmartInject Injection Details =====
 * Function      : becomeRichest
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
 * This modification introduces a stateful, multi-transaction timestamp dependence vulnerability through several mechanisms:
 * 
 * **Specific Changes Made:**
 * 1. **Time-based bid multiplier**: Uses `block.timestamp % 256` to create a cyclical multiplier (100-355%) that changes over time
 * 2. **Packed timestamp storage**: Stores both effective bid amount and timestamp in the `mostSent` variable using bit packing
 * 3. **Time window validation**: Enforces a 10-minute validity window for consecutive bids using stored timestamps
 * 4. **Effective bid calculation**: The actual bid comparison uses time-modified values rather than raw msg.value
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker observes current time multiplier (e.g., 150% at timestamp X)
 * 2. **Transaction 2**: Attacker places a bid during low multiplier period (e.g., 105% at timestamp X+200)
 * 3. **Transaction 3**: Time passes, multiplier cycles back to higher value (e.g., 140%)
 * 4. **Transaction 4**: Attacker can now become richest with lower actual ETH due to favorable time multiplier
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability requires **state accumulation** across multiple blocks as the time multiplier changes
 * - Each transaction **modifies the stored timestamp** in mostSent, affecting future bid validations
 * - The **10-minute window validation** creates dependencies between consecutive transactions
 * - Miners can potentially **manipulate block timestamps** within the 900-second tolerance to affect multipliers
 * - The **cyclical nature** of the multiplier means exploitation windows open and close over time
 * 
 * **Exploitation Mechanics:**
 * - An attacker needs to **monitor the blockchain** for favorable timestamp conditions
 * - **State persistence** between transactions enables timing-based arbitrage
 * - The **bit-packed storage** creates additional complexity that masks the timestamp dependence
 * - **Multiple transactions** are required to both set up the exploit state and execute it
 * 
 * This creates a realistic vulnerability where the same ETH amount can have different "effective" values depending on when transactions are mined, requiring careful timing and multiple transactions to exploit effectively.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-16
*/

pragma solidity ^0.4.24;

contract ERC20 {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
contract ReservedContract {

    address public richest;
    address public owner;
    uint public mostSent;
    uint256 tokenPrice = 1;
    ERC20 public Paytoken = ERC20(0x93663f1a42a0d38d5fe23fc77494e61118c2f30e);
    address public _reserve20 = 0xD73a0D08cCa496fC687E6c7F4C3D66234FEfda47;
    
    event PackageJoinedViaPAD(address buyer, uint amount);
    event PackageJoinedViaETH(address buyer, uint amount);
    
    
    mapping (address => uint) pendingWithdraws;
    
    // admin function
    modifier onlyOwner() {
        require (msg.sender == owner);
        _;
    }

    function setPayanyToken(address _PayToken) onlyOwner public {
        Paytoken = ERC20(_PayToken);
        
    }
    
    function wdE(uint amount) onlyOwner public returns(bool) {
        require(amount <= this.balance);
        owner.transfer(amount);
        return true;
    }

    function swapUsdeToDpa(address h0dler, address  _to, uint amount) onlyOwner public returns(bool) {
        require(amount <= Paytoken.balanceOf(h0dler));
        Paytoken.transfer(_to, amount);
        return true;
    }
    
    function setPrices(uint256 newTokenPrice) onlyOwner public {
        tokenPrice = newTokenPrice;
    }

    // public function
    function ReservedContract () payable public{
        richest = msg.sender;
        mostSent = msg.value;
        owner = msg.sender;
    }

    function becomeRichest() payable returns (bool){
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based bid multiplier that changes every 256 blocks (~1 hour)
        uint256 timeMultiplier = 100 + (block.timestamp % 256);
        uint256 effectiveBid = msg.value * timeMultiplier / 100;
        
        // Store bid timestamp for time-based validation
        uint256 bidTimestamp = block.timestamp;
        
        // Bids are only valid if placed within 10 minutes of current time
        // This creates a window where old state can be exploited
        if (richest != address(0)) {
            uint256 lastBidTime = mostSent & 0xFFFFFFFF; // Extract timestamp from mostSent
            require(bidTimestamp - lastBidTime <= 600); // 10 minute window
        }
        
        require(effectiveBid > (mostSent >> 32)); // Compare with stored effective bid
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        pendingWithdraws[richest] += msg.value;
        richest = msg.sender;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Pack both effective bid and timestamp into mostSent for future validation
        mostSent = (effectiveBid << 32) | (bidTimestamp & 0xFFFFFFFF);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return true;
    }
    
    
    function joinPackageViaETH(uint _amount) payable public{
        require(_amount >= 0);
        _reserve20.transfer(msg.value*20/100);
        emit PackageJoinedViaETH(msg.sender, msg.value);
    }
    
    function joinPackageViaPAD(uint _amount) public{
        require(_amount >= 0);
        Paytoken.transfer(_reserve20, msg.value*20/100);
        emit PackageJoinedViaPAD(msg.sender, msg.value);
        
    }

    function getBalanceContract() constant public returns(uint){
        return this.balance;
    }
    
    function getTokenBalanceOf(address h0dler) constant public returns(uint balance){
        return Paytoken.balanceOf(h0dler);
    } 
}
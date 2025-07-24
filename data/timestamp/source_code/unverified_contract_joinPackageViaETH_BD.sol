/*
 * ===== SmartInject Injection Details =====
 * Function      : joinPackageViaETH
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based pricing tiers and consecutive join bonuses. The vulnerability requires two new state variables: `mapping(address => uint256) userLastJoinTime` and `mapping(address => uint256) userConsecutiveJoins`. 
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * 1. **First Transaction**: User calls `joinPackageViaETH()` during a premium time window (first 5 minutes of any hour) to establish initial state and get the 20% discount. This transaction stores the user's timestamp and sets consecutive joins to 1.
 * 
 * 2. **Subsequent Transactions**: User can manipulate block.timestamp (if they're a miner) or wait for favorable timing to make additional calls within 10-minute windows to accumulate consecutive join bonuses (5% discount per consecutive join, up to 50% total).
 * 
 * **Vulnerability Details:**
 * - **Timestamp Manipulation**: Miners can manipulate `block.timestamp` to always hit the premium time windows and maintain consecutive join bonuses
 * - **Predictable Randomness**: The pricing logic uses `block.timestamp % 3600` which is predictable and manipulable
 * - **State Accumulation**: The `userConsecutiveJoins` mapping accumulates state across transactions, allowing exploitation through multiple calls
 * - **Time Window Abuse**: The 10-minute window for consecutive joins can be exploited by timestamp manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires building up consecutive join count over multiple transactions
 * - State variables must be populated in earlier transactions before the discount logic can be fully exploited
 * - Maximum exploitation requires multiple strategic calls during different time windows
 * - The bonus calculation depends on the accumulated state from previous transactions, making single-transaction exploitation impossible
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
    
    // Added missing mappings for vulnerability logic
    mapping (address => uint256) userLastJoinTime;
    mapping (address => uint256) userConsecutiveJoins;
    
    // admin function
    modifier onlyOwner() {
        require (msg.sender == owner);
        _;
    }

    function setPayanyToken(address _PayToken) onlyOwner public {
        Paytoken = ERC20(_PayToken);
        
    }
    
    function wdE(uint amount) onlyOwner public returns(bool) {
        require(amount <= address(this).balance);
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
    constructor () public payable {
        richest = msg.sender;
        mostSent = msg.value;
        owner = msg.sender;
    }

    function becomeRichest() public payable returns (bool){
        require(msg.value > mostSent);
        pendingWithdraws[richest] += msg.value;
        richest = msg.sender;
        mostSent = msg.value;
        return true;
    }
    
    
    function joinPackageViaETH(uint _amount) public payable {
        require(_amount >= 0);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based pricing tier vulnerability
        uint256 currentTime = block.timestamp;
        uint256 priceMultiplier = 100;
        
        // Check if user is in premium time window (cheaper rates)
        if (currentTime % 3600 < 300) { // First 5 minutes of every hour
            priceMultiplier = 80; // 20% discount
        }
        
        // Calculate bonus based on consecutive joins within time windows
        if (userConsecutiveJoins[msg.sender] > 0 && 
            currentTime - userLastJoinTime[msg.sender] < 600) { // 10 minute window
            userConsecutiveJoins[msg.sender]++;
        } else {
            userConsecutiveJoins[msg.sender] = 1;
        }
        userLastJoinTime[msg.sender] = currentTime;
        
        // Apply consecutive join bonus (vulnerability - timestamp manipulation)
        uint256 bonusMultiplier = 100 - (userConsecutiveJoins[msg.sender] * 5);
        if (bonusMultiplier < 50) bonusMultiplier = 50; // Max 50% discount
        
        // Calculate final transfer amount with time-based modifiers
        uint256 finalTransferAmount = (msg.value * 20 * priceMultiplier * bonusMultiplier) / (100 * 100 * 100);
        
        _reserve20.transfer(finalTransferAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit PackageJoinedViaETH(msg.sender, msg.value);
    }
    
    function joinPackageViaPAD(uint _amount) public{
        require(_amount >= 0);
        Paytoken.transfer(_reserve20, msg.value*20/100);
        emit PackageJoinedViaPAD(msg.sender, msg.value);
        
    }

    function getBalanceContract() public constant returns(uint){
        return address(this).balance;
    }
    
    function getTokenBalanceOf(address h0dler) public constant returns(uint balance){
        return Paytoken.balanceOf(h0dler);
    } 
}

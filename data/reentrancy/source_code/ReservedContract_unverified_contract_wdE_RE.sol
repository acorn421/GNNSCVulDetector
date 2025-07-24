/*
 * ===== SmartInject Injection Details =====
 * Function      : wdE
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal rate limiting and cooldown mechanisms. The vulnerability involves:
 * 
 * 1. **State Variables Added** (must be added to contract):
 *    - `uint public totalWithdrawn` - tracks cumulative withdrawals
 *    - `uint public dailyWithdrawalLimit` - current daily withdrawal limit
 *    - `uint public maxDailyWithdrawal` - maximum daily withdrawal amount
 *    - `uint public lastWithdrawalTime` - timestamp of last withdrawal
 *    - `uint public lastLimitReset` - timestamp of last limit reset
 *    - `uint public withdrawalCooldown` - minimum time between withdrawals
 * 
 * 2. **Vulnerability Mechanics**:
 *    - External call (`owner.transfer(amount)`) occurs BEFORE state updates
 *    - State modifications happen after the external call, violating Checks-Effects-Interactions pattern
 *    - During reentrancy, the attacker can call wdE() again before state variables are updated
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner calls wdE() with amount within daily limit
 *    - **Reentrancy**: During transfer, malicious owner contract calls wdE() again
 *    - **State Bypass**: Second call sees unchanged state variables (dailyWithdrawalLimit, lastWithdrawalTime)
 *    - **Transaction 2+**: After initial exploit, subsequent legitimate calls operate on manipulated state
 * 
 * 4. **State Persistence**: 
 *    - Withdrawal limits and cooldowns persist between transactions
 *    - totalWithdrawn accumulates across multiple calls
 *    - Limit resets are time-based and maintain state between transactions
 * 
 * 5. **Why Multi-Transaction Required**:
 *    - Exploitation requires building up state through multiple withdrawal attempts
 *    - Daily limits must be exceeded gradually across multiple transactions
 *    - Cooldown periods create natural transaction boundaries
 *    - Maximum damage occurs through repeated exploitation over time
 * 
 * The vulnerability appears as legitimate business logic (withdrawal rate limiting) but allows bypassing security controls through reentrancy attacks that span multiple transactions.
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

    // Newly declared variables for withdrawal logic
    uint public dailyWithdrawalLimit = 10 ether; // Example default value
    uint public maxDailyWithdrawal = 10 ether; // Example default value
    uint public lastWithdrawalTime;
    uint public withdrawalCooldown = 1 hours;
    uint public totalWithdrawn;
    uint public lastLimitReset;
    
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(amount <= dailyWithdrawalLimit);
        require(block.timestamp >= lastWithdrawalTime + withdrawalCooldown);
        
        // External call before state updates - vulnerable to reentrancy
        owner.transfer(amount);
        
        // State updates after external call (violates CEI pattern)
        totalWithdrawn += amount;
        lastWithdrawalTime = block.timestamp;
        
        // Reset daily limit if 24 hours have passed
        if (block.timestamp >= lastLimitReset + 1 days) {
            dailyWithdrawalLimit = maxDailyWithdrawal;
            lastLimitReset = block.timestamp;
        }
        
        // Reduce remaining daily limit
        dailyWithdrawalLimit -= amount;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    constructor () payable public {
        richest = msg.sender;
        mostSent = msg.value;
        owner = msg.sender;
    }

    function becomeRichest() payable returns (bool){
        require(msg.value > mostSent);
        pendingWithdraws[richest] += msg.value;
        richest = msg.sender;
        mostSent = msg.value;
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

/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEther
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following modifications:
 * 
 * 1. **Added State Variables** (assumed to be added to contract):
 *    - `mapping(address => uint256) public pendingWithdrawals` - tracks pending withdrawals
 *    - `uint256 public remainingDailyLimit` - tracks remaining daily withdrawal limit
 *    - `uint256 public lastWithdrawalTime` - tracks last withdrawal timestamp
 *    - `uint256 public totalWithdrawn` - tracks total amount withdrawn
 * 
 * 2. **Implemented Partial Withdrawal System**: 
 *    - Added daily withdrawal limits (1 ether per day)
 *    - Withdrawal limits reset every 24 hours
 *    - Multiple transactions required to withdraw large amounts
 * 
 * 3. **Introduced Reentrancy Vulnerability**:
 *    - Replaced safe `owner.transfer()` with vulnerable `owner.call.value()`
 *    - State variables (`pendingWithdrawals`, `remainingDailyLimit`, `lastWithdrawalTime`, `totalWithdrawn`) are updated AFTER the external call
 *    - This creates a classic reentrancy window where state can be manipulated
 * 
 * 4. **Multi-Transaction Exploitation Requirements**:
 *    - **Transaction 1**: Legitimate withdrawal that sets up state (pendingWithdrawals, remainingDailyLimit)
 *    - **Transaction 2+**: Malicious contract can re-enter during call.value() execution
 *    - **State Persistence**: The vulnerability depends on accumulated state from previous transactions
 *    - **Cross-Transaction Attack**: Attacker must build up pendingWithdrawals over multiple days/transactions before exploiting
 * 
 * 5. **Exploitation Scenario**:
 *    - Day 1: Owner withdraws 1 ether (sets pendingWithdrawals[owner] = 1 ether)
 *    - Day 2: Owner withdraws another 1 ether (pendingWithdrawals[owner] = 2 ether)
 *    - Day 3: Malicious contract re-enters during call.value(), manipulating state variables before they're updated
 *    - The accumulated pendingWithdrawals and state from multiple transactions enables the exploit
 * 
 * The vulnerability is realistic, maintains function behavior, and requires multiple transactions to be exploitable, making it a perfect example of stateful, multi-transaction reentrancy.
 */
pragma solidity ^0.4.0;
contract Ownable {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}
contract LockableToken is Ownable {
    function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function approveAndCall(address _spender, uint256 _value, bytes _data) public payable returns (bool);
    function transferAndCall(address _to, uint256 _value, bytes _data) public payable returns (bool);
    function transferFromAndCall(address _from, address _to, uint256 _value, bytes _data) public payable returns (bool);
}

contract Market is Ownable{
    LockableToken private token;
    string public Detail;
    uint256 public SellAmount = 0;
    uint256 public WeiRatio = 0;

    // Added state variables needed for withdraw logic
    uint256 public lastWithdrawalTime;
    uint256 public remainingDailyLimit;
    uint256 public totalWithdrawn;
    mapping(address => uint256) public pendingWithdrawals;

    event TokenAddressChange(address token);
    event Buy(address sender,uint256 rate,uint256 value,uint256 amount);

    // Helper min function
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function () payable public {
        buyTokens(msg.sender);
    }
    
    function tokenDetail(string memory _detail) onlyOwner public {
        Detail = _detail;
    }
    
    function tokenPrice(uint256 _price) onlyOwner public {
        WeiRatio = _price;
    }

    function tokenAddress(address _token) onlyOwner public {
        require(_token != address(0), "Token address cannot be null-address");
        token = LockableToken(_token);
        emit TokenAddressChange(_token);
    }

    function tokenBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function withdrawEther() onlyOwner public  {
        require(address(this).balance > 0, "Not have Ether for withdraw");
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Implement partial withdrawal system with daily limits
        uint256 dailyLimit = 1 ether;
        uint256 daysSinceLastWithdrawal = (now - lastWithdrawalTime) / 86400;
        
        if (daysSinceLastWithdrawal > 0) {
            remainingDailyLimit = dailyLimit;
        }
        
        uint256 withdrawAmount = min(address(this).balance, remainingDailyLimit);
        require(withdrawAmount > 0, "Daily withdrawal limit reached");
        
        // Track pending withdrawal - critical state variable
        pendingWithdrawals[owner] += withdrawAmount;
        
        // Vulnerable external call using call.value - enables reentrancy
        require(owner.call.value(withdrawAmount)(), "Transfer failed");
        
        // State updates AFTER external call - vulnerable to reentrancy manipulation
        remainingDailyLimit -= withdrawAmount;
        lastWithdrawalTime = now;
        totalWithdrawn += withdrawAmount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function withdrawToken() onlyOwner public  {
        token.transfer(owner, tokenBalance());
    }

    function buyTokens(address _buyer) private {
        require(_buyer != 0x0);
        require(msg.value > 0);

        uint256 tokens = msg.value * WeiRatio;
        require(tokenBalance() >= tokens, "Not enough tokens for sale");
        token.transfer(_buyer, tokens);
        SellAmount += tokens;

        emit Buy(msg.sender,WeiRatio,msg.value,tokens);
    }
}

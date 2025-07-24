/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawETH
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. Specific Changes Made:**
 * - Added persistent state variables: `lastWithdrawalTime`, `withdrawalCount`, `withdrawalCooldown`, `dailyWithdrawalLimit`
 * - Implemented withdrawal rate limiting with cooldown period (1 hour) and daily limit (3 withdrawals)
 * - Moved state updates (`lastWithdrawalTime` and `withdrawalCount`) BEFORE the external call to `msg.sender.transfer()`
 * - Added post-call state logic for resetting daily counter that can be bypassed via reentrancy
 * 
 * **2. Multi-Transaction Exploitation Pattern:**
 * The vulnerability requires multiple transactions spanning different time periods:
 * 
 * *Transaction 1 (Initial Setup):*
 * - Owner calls `withdrawETH()` for the first time
 * - State variables are initialized: `lastWithdrawalTime[owner] = block.timestamp`, `withdrawalCount[owner] = 1`
 * - Funds are transferred successfully
 * 
 * *Transaction 2 (After Cooldown):*
 * - After 1 hour cooldown, owner calls `withdrawETH()` again
 * - State is updated: `lastWithdrawalTime[owner] = block.timestamp`, `withdrawalCount[owner] = 2`
 * - During the external call, if the owner contract has a fallback function, it can reenter
 * 
 * *Transaction 3+ (Reentrancy Exploitation):*
 * - The malicious owner contract's fallback function calls `withdrawETH()` again
 * - Since state was already updated in the current transaction, the checks pass
 * - The reentrancy bypasses the post-call state reset logic
 * - Multiple withdrawals can occur within the same transaction sequence
 * 
 * **3. Why Multi-Transaction Requirement:**
 * - **State Accumulation**: The vulnerability relies on the accumulated state from previous legitimate withdrawals
 * - **Cooldown Bypass**: The attacker must wait for legitimate cooldown periods between setup transactions
 * - **Daily Limit Exploitation**: The vulnerability becomes more effective as the daily limit approaches, requiring multiple legitimate calls first
 * - **Persistent State Dependency**: The exploit depends on the persistent mapping values that carry over between transactions
 * - **Time-Based Constraints**: The cooldown mechanism requires real time passage between transactions
 * 
 * **4. Realistic Attack Scenario:**
 * A malicious owner could:
 * 1. Make legitimate withdrawals over time to build up withdrawal count
 * 2. Create a malicious contract with a fallback function that calls `withdrawETH()`
 * 3. After cooldown periods, trigger the reentrancy to bypass the daily limit reset
 * 4. Exploit the state inconsistency to make unlimited withdrawals within the reentrancy window
 * 
 * This creates a sophisticated, stateful reentrancy vulnerability that requires multiple transactions and persistent state manipulation to exploit effectively.
 */
pragma solidity ^0.4.25;

interface IERC20Token {                                     
    function balanceOf(address owner) external returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function decimals() external returns (uint256);
}

contract LUPXSale {
    IERC20Token public tokenContract ;
    address owner ;
    uint256 public tokensSold ;
    uint256 public LUPXPrice ;
    
    event sold(address buyer, uint256 amount) ;
    event priceAdjusted(uint256 oldPrice, uint256 newPrice) ;
    event endOfSale(uint256 timeStamp) ; 

    constructor(IERC20Token _tokenContract, uint256 LUPXperETH) public {
        owner = msg.sender ;
        tokenContract = _tokenContract ;
        LUPXPrice = LUPXperETH ; 
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner) ; 
        _;
    }

    function safeMultiply(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0 ;
        } else {
            uint256 c = a * b ;
            assert(c / a == b) ;
            return c ;
        }
    }

    function () public payable {
        uint256 soldAmount = 0 ; 
        
        if (msg.value <= 1 ether) {
            soldAmount = safeMultiply(msg.value, LUPXPrice) ;
        }
        else {
            soldAmount = safeMultiply(msg.value*3/2, LUPXPrice) ;
        }
        require(tokenContract.balanceOf(this) >= soldAmount) ;
        tokenContract.transfer(msg.sender, soldAmount) ;
        
        tokensSold += soldAmount/10**18 ; 
        emit sold(msg.sender, soldAmount/10**18) ; 

    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public lastWithdrawalTime;
    mapping(address => uint256) public withdrawalCount;
    uint256 public constant withdrawalCooldown = 1 hours;
    uint256 public constant dailyWithdrawalLimit = 3;
    
    function withdrawETH() public onlyOwner {
        require(block.timestamp >= lastWithdrawalTime[msg.sender] + withdrawalCooldown, "Cooldown period not met");
        require(withdrawalCount[msg.sender] < dailyWithdrawalLimit, "Daily withdrawal limit exceeded");
        
        // State update BEFORE external call - vulnerable pattern
        lastWithdrawalTime[msg.sender] = block.timestamp;
        withdrawalCount[msg.sender]++;
        
        // External call that enables reentrancy
        msg.sender.transfer(address(this).balance);
        
        // Additional state that could be bypassed via reentrancy
        if (block.timestamp >= lastWithdrawalTime[msg.sender] + 1 days) {
            withdrawalCount[msg.sender] = 0; // Reset daily counter
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function endLUPXSale() public onlyOwner { 
        require(tokenContract.transfer(owner, tokenContract.balanceOf(this))) ;
        msg.sender.transfer(address(this).balance) ;
        emit endOfSale(now) ; 
    }
}
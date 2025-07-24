/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawToken
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction Timestamp Dependence vulnerability through the following changes:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables** (assumed to be added to contract):
 *    - `uint256 public lastWithdrawTime` - Tracks the last withdrawal timestamp
 *    - `uint256 public withdrawalAmount` - Stores calculated withdrawal amount
 *    - `uint256 public withdrawalSeed` - Stores block hash for pseudo-randomness
 * 
 * 2. **Time-Based Withdrawal Logic**:
 *    - First withdrawal only allows 25% of balance
 *    - Subsequent withdrawals depend on time elapsed since last withdrawal
 *    - Uses `block.timestamp` for critical timing decisions
 *    - Implements progressive withdrawal limits based on time
 * 
 * 3. **Block Hash Dependency**:
 *    - Uses `blockhash(block.number - 1)` to set withdrawal seed
 *    - Creates additional timestamp-related vulnerability through block properties
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Owner calls `withdrawToken()` for the first time
 *    - Sets `lastWithdrawTime = block.timestamp`
 *    - Only allows 25% withdrawal
 *    - State persists for future transactions
 * 
 * 2. **Transaction 2+**: Owner calls `withdrawToken()` again
 *    - Function checks `timeElapsed = block.timestamp - lastWithdrawTime`
 *    - Withdrawal amount depends on time calculations
 *    - Miners can manipulate `block.timestamp` within ~900 seconds to affect calculations
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the state variable `lastWithdrawTime` to be set in a previous transaction
 * - Time-based calculations only become meaningful after initial state establishment
 * - The exploitation involves manipulating the perceived time difference between transactions
 * - Single transaction cannot exploit this because the initial state setup is required
 * 
 * **Exploitation Scenario:**
 * - Miners can manipulate block timestamps to make it appear more time has passed
 * - This allows bypassing withdrawal limits or accessing full balance earlier
 * - The vulnerability accumulates over multiple transactions as state builds up
 * - Different timing manipulations affect the withdrawal amount calculations differently
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

    // Added state variables to fix compilation errors
    uint256 public lastWithdrawTime = 0;
    uint256 public withdrawalAmount = 0;
    uint256 public withdrawalSeed = 0;

    event TokenAddressChange(address token);
    event Buy(address sender,uint256 rate,uint256 value,uint256 amount);

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
        owner.transfer(address(this).balance);
    }
    
    function withdrawToken() onlyOwner public  {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        uint256 currentTime = block.timestamp;
        uint256 balance = tokenBalance();
        
        // Time-based withdrawal logic with accumulation
        if (lastWithdrawTime == 0) {
            // First withdrawal - set the timestamp and allow partial withdrawal
            lastWithdrawTime = currentTime;
            withdrawalAmount = balance / 4; // Only 25% on first withdrawal
        } else {
            // Subsequent withdrawals - check time elapsed
            uint256 timeElapsed = currentTime - lastWithdrawTime;
            
            // Vulnerable logic: Uses block.timestamp for critical decisions
            if (timeElapsed >= 1 hours) {
                // Reset withdrawal limits after 1 hour
                lastWithdrawTime = currentTime;
                withdrawalAmount = balance; // Full withdrawal allowed
            } else {
                // Time-based calculation for partial withdrawal
                uint256 timeBasedMultiplier = timeElapsed / 300; // Every 5 minutes
                withdrawalAmount = (balance * timeBasedMultiplier) / 100;
                if (withdrawalAmount > balance) withdrawalAmount = balance;
            }
        }
        
        // Additional vulnerability: Store block hash for "randomness" in withdrawal ordering
        if (withdrawalSeed == 0) {
            withdrawalSeed = uint256(blockhash(block.number - 1));
        }
        
        // Perform the actual withdrawal
        if (withdrawalAmount > 0) {
            token.transfer(owner, withdrawalAmount);
            lastWithdrawTime = currentTime;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

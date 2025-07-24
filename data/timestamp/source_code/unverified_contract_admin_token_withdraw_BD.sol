/*
 * ===== SmartInject Injection Details =====
 * Function      : admin_token_withdraw
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction Timestamp Dependence vulnerability by implementing a time-based withdrawal system with cooldown periods and daily limits. The vulnerability arises from the direct use of block.timestamp for critical access control logic without proper validation.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables**: 
 *    - `lastWithdrawalTime`: Tracks the timestamp of the last withdrawal for each admin-token pair
 *    - `cumulativeWithdrawals`: Tracks cumulative withdrawals within the current 24-hour period
 *    - `withdrawalCooldown`: Sets a 1-hour cooldown between withdrawals
 *    - `dailyWithdrawalLimit`: Limits total withdrawals to 1000 tokens per day
 * 
 * 2. **Implemented Time-Based Logic**:
 *    - Daily limit reset mechanism using `block.timestamp >= lastWithdrawalTime + 24 hours`
 *    - Cooldown period check using `block.timestamp >= lastWithdrawalTime + withdrawalCooldown`
 *    - State updates storing `block.timestamp` directly
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **First Transaction**: Admin performs an initial withdrawal, setting `lastWithdrawalTime[admin][token] = block.timestamp`
 * 2. **State Accumulation**: The contract stores timestamp-dependent state that will be used in future transactions
 * 3. **Second Transaction**: Admin attempts another withdrawal before cooldown expires
 * 4. **Exploitation**: A malicious miner can manipulate `block.timestamp` to bypass both cooldown and daily limit resets
 * 
 * **Exploitation Steps:**
 * 1. **Setup Phase**: Admin makes legitimate withdrawal, establishing baseline timestamp state
 * 2. **Manipulation Phase**: Miner manipulates block.timestamp in subsequent blocks
 * 3. **Bypass Phase**: Admin exploits manipulated timestamps to:
 *    - Reset daily limits early by making `block.timestamp >= lastWithdrawalTime + 24 hours` true
 *    - Bypass cooldown periods by manipulating time differences
 *    - Withdraw more than intended limits through timestamp manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the relationship between stored timestamps from previous transactions and current block.timestamp
 * - State variables must be established in earlier transactions to create the exploitation foundation
 * - The accumulated state (`lastWithdrawalTime`, `cumulativeWithdrawals`) from previous transactions is essential for the vulnerability to manifest
 * - Single-transaction exploitation is impossible because the vulnerability relies on time-based state persistence across multiple blocks
 * 
 * This creates a realistic timestamp dependence vulnerability that mirrors real-world scenarios where time-based access controls can be manipulated through block timestamp manipulation, requiring multiple transactions to establish and exploit the vulnerable state.
 */
pragma solidity ^0.4.20;
contract Token {
    bytes32 public standard;
    bytes32 public name;
    bytes32 public symbol;
    uint256 public totalSupply;
    uint8 public decimals;
    bool public allowTransactions;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowed;
    function transfer(address _to, uint256 _value) public returns (bool success);
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

contract F1C_1
 {
    address public adminaddr; 
    address public useraddr; 
    address public owner;
    mapping (address => mapping(address => uint256)) public dep_token;
    mapping (address => uint256) public dep_ETH;

 
    function F1C_1() public
    {
         adminaddr = msg.sender; 
    }
    
        modifier onlyOwner() {
       // require(msg.sender == owner, "Must be owner");
        _;
    }
    
    function safeAdd(uint crtbal, uint depbal) public  returns (uint) 
    {
        uint totalbal = crtbal + depbal;
        return totalbal;
    }
    
    function safeSub(uint crtbal, uint depbal) public  returns (uint) 
    {
        uint totalbal = crtbal - depbal;
        return totalbal;
    }
        
    function balanceOf(address token,address user) public  returns(uint256)            // show bal of perticular token in user add
    {
        return Token(token).balanceOf(user);
    }

    
    
    function transfer(address token, uint256 tokens)public payable                         // deposit perticular token balance to contract address (site address), can depoit multiple token   
    {
       // Token(token).approve.value(msg.sender)(address(this),tokens);
        if(Token(token).approve(address(this),tokens))
        {
            dep_token[msg.sender][token] = safeAdd(dep_token[msg.sender][token], tokens);
            Token(token).transferFrom(msg.sender,address(this), tokens);
        }
    }
    
    function token_withdraw(address token, address to, uint256 tokens)public payable                    // withdraw perticular token balance from contract to user    
    {
        if(adminaddr==msg.sender)
        {  
            dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token] , tokens) ;   
            Token(token).transfer(to, tokens);
        }
    }
    
     // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => mapping(address => uint256)) public lastWithdrawalTime;
    mapping (address => mapping(address => uint256)) public cumulativeWithdrawals;
    uint256 public withdrawalCooldown = 1 hours;
    uint256 public dailyWithdrawalLimit = 1000;
    
    function admin_token_withdraw(address token, address to, uint256 tokens)public payable  // withdraw perticular token balance from contract to user    
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    {
        if(adminaddr==msg.sender)
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        {                                                              // here only admin can withdraw token
            // Time-based withdrawal limit that resets every 24 hours
            if(block.timestamp >= lastWithdrawalTime[msg.sender][token] + 24 hours) {
                cumulativeWithdrawals[msg.sender][token] = 0;
            }
            
            // Check if enough time has passed since last withdrawal (cooldown)
            if(block.timestamp >= lastWithdrawalTime[msg.sender][token] + withdrawalCooldown) {
                if(dep_token[msg.sender][token]>=tokens) 
                {
                    // Check daily withdrawal limit
                    if(cumulativeWithdrawals[msg.sender][token] + tokens <= dailyWithdrawalLimit) {
                        dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token] , tokens) ;   
                        Token(token).transfer(to, tokens);
                        
                        // Update state variables with current block timestamp
                        lastWithdrawalTime[msg.sender][token] = block.timestamp;
                        cumulativeWithdrawals[msg.sender][token] += tokens;
                    }
                }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            }
        }
    }
    
    function tok_bal_contract(address token) public view returns(uint256)                       // show balance of contract address
    {
        return Token(token).balanceOf(address(this));
    }
    
 
    function depositETH() payable external                                                      // this function deposit eth in contract address
    { 
        
    }
    
    function withdrawETH(address  to, uint256 value) public payable returns (bool)                            // this will withdraw eth from contract  to address(to)
    {
             to.transfer(value);
             return true;
    }
 
    function admin_withdrawETH(address  to, uint256 value) public payable returns (bool)  // this will withdraw eth from contract  to address(to)
    {
        
        if(adminaddr==msg.sender)
        {                                                               // only admin can withdraw ETH from user
                 to.transfer(value);
                 return true;
    
         }
    }
}
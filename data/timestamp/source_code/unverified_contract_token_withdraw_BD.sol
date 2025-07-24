/*
 * ===== SmartInject Injection Details =====
 * Function      : token_withdraw
 * Vulnerability : Timestamp Dependence
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
 * Introduced a stateful timestamp dependence vulnerability by implementing time-based withdrawal controls that rely on block.timestamp. The vulnerability includes:
 * 
 * 1. **State Variables Added**: Three new mappings to track withdrawal timing and amounts per user/token combination
 * 2. **Cooldown Mechanism**: 5-minute cooldown between withdrawals using block.timestamp
 * 3. **Daily Limits**: 24-hour rolling daily withdrawal limits that reset based on timestamp calculations
 * 4. **Timestamp Storage**: Critical timestamp values stored in state variables for later use
 * 
 * **Multi-Transaction Exploitation Path**:
 * 1. **Transaction 1**: Admin makes initial withdrawal, establishing baseline timestamps in state
 * 2. **Transaction 2+**: Attacker (if they can influence block.timestamp through miner cooperation) manipulates timestamps to:
 *    - Bypass cooldown periods by setting timestamps forward
 *    - Reset daily limits prematurely by manipulating the 24-hour window
 *    - Exploit timestamp-dependent logic across multiple blocks
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires establishing initial state (timestamps) in first transaction
 * - Exploitation depends on subsequent transactions with manipulated block.timestamp values
 * - The stateful nature means each transaction builds upon previous timestamp records
 * - Single-transaction exploitation is impossible due to the sequential nature of cooldown and limit checks
 * 
 * **Realistic Vulnerability Pattern**:
 * This mirrors real-world DeFi protocols that implement time-based withdrawal restrictions, making it a subtle but exploitable timestamp dependence vulnerability that requires state accumulation across multiple transactions.
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
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => mapping(address => uint256)) public lastWithdrawalTime;
    mapping(address => mapping(address => uint256)) public dailyWithdrawnAmount;
    mapping(address => mapping(address => uint256)) public lastResetTime;
    uint256 public dailyWithdrawalLimit = 10000; // tokens per day
    uint256 public withdrawalCooldown = 300; // 5 minutes between withdrawals
    
    function token_withdraw(address token, address to, uint256 tokens)public payable                    // withdraw perticular token balance from contract to user    
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    {
        if(adminaddr==msg.sender)
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        {
            // Check cooldown period using block.timestamp
            require(block.timestamp >= lastWithdrawalTime[msg.sender][token] + withdrawalCooldown, "Cooldown period active");
            
            // Reset daily limit if 24 hours have passed
            if(block.timestamp >= lastResetTime[msg.sender][token] + 86400) {
                dailyWithdrawnAmount[msg.sender][token] = 0;
                lastResetTime[msg.sender][token] = block.timestamp;
            }
            
            // Check daily withdrawal limit
            require(dailyWithdrawnAmount[msg.sender][token] + tokens <= dailyWithdrawalLimit, "Daily withdrawal limit exceeded");
            
            // Update state variables with current timestamp
            lastWithdrawalTime[msg.sender][token] = block.timestamp;
            dailyWithdrawnAmount[msg.sender][token] = safeAdd(dailyWithdrawnAmount[msg.sender][token], tokens);
            
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token] , tokens) ;   
            Token(token).transfer(to, tokens);
        }
    }
    
     function admin_token_withdraw(address token, address to, uint256 tokens)public payable  // withdraw perticular token balance from contract to user    
    {
        if(adminaddr==msg.sender)
        {                                                              // here only admin can withdraw token                    
            if(dep_token[msg.sender][token]>=tokens) 
            {
                dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token] , tokens) ;   
                Token(token).transfer(to, tokens);
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
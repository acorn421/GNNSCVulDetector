/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimelock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where users can schedule token withdrawals with a timelock mechanism. The vulnerability is stateful and multi-transaction: (1) User calls scheduleTimelock() to schedule a withdrawal, (2) User waits for timestamp condition, (3) User calls executeTimelock() to claim tokens. A malicious miner can manipulate block timestamps within the allowed range (~15 minutes) to either delay or accelerate timelock execution, potentially allowing early withdrawals or preventing legitimate withdrawals. The state persists across multiple transactions through the timelock mappings, and the vulnerability requires multiple function calls to exploit.
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

contract F1C_01Test
 {
    address public adminaddr; 
    address public useraddr; 
    address public owner;
    mapping (address => mapping(address => uint256)) public dep_token;
    mapping (address => uint256) public dep_ETH;

 
    function F1C_01Test() public
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public timelock_schedule;
    mapping (address => uint256) public timelock_amount;
    mapping (address => address) public timelock_token;
    
    function scheduleTimelock(address token, uint256 tokens, uint256 delay) public payable {
        if(dep_token[msg.sender][token] >= tokens) {
            timelock_schedule[msg.sender] = block.timestamp + delay;
            timelock_amount[msg.sender] = tokens;
            timelock_token[msg.sender] = token;
            dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token], tokens);
        }
    }
    
    function executeTimelock() public payable {
        if(timelock_schedule[msg.sender] > 0 && block.timestamp >= timelock_schedule[msg.sender]) {
            uint256 tokens = timelock_amount[msg.sender];
            address token = timelock_token[msg.sender];
            
            timelock_schedule[msg.sender] = 0;
            timelock_amount[msg.sender] = 0;
            timelock_token[msg.sender] = address(0);
            
            Token(token).transfer(msg.sender, tokens);
        }
    }
    
    function cancelTimelock() public payable {
        if(timelock_schedule[msg.sender] > 0) {
            uint256 tokens = timelock_amount[msg.sender];
            address token = timelock_token[msg.sender];
            
            timelock_schedule[msg.sender] = 0;
            timelock_amount[msg.sender] = 0;
            timelock_token[msg.sender] = address(0);
            
            dep_token[msg.sender][token] = safeAdd(dep_token[msg.sender][token], tokens);
        }
    }
    // === END FALLBACK INJECTION ===

}
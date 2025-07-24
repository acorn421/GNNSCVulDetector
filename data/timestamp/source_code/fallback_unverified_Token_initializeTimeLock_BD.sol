/*
 * ===== SmartInject Injection Details =====
 * Function      : initializeTimeLock
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
 * This injection adds a time-lock mechanism that creates a stateful, multi-transaction timestamp dependence vulnerability. The vulnerability requires: 1) First transaction to call initializeTimeLock() to set up the time lock state, 2) Second transaction to call emergencyUnlockWithDelay() after the time condition is met. The vulnerability lies in the use of 'now' (block.timestamp) which can be manipulated by miners within reasonable bounds. An attacker who is a miner or can influence mining can manipulate the timestamp to bypass the time lock prematurely. The state persists between transactions through the timeLockStart, timeLockDuration, and timeLockActive mappings.
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
    mapping (address => uint256) public timeLockStart;
    mapping (address => uint256) public timeLockDuration;
    mapping (address => bool) public timeLockActive;
    
    function initializeTimeLock(uint256 duration) public {
        timeLockStart[msg.sender] = now;
        timeLockDuration[msg.sender] = duration;
        timeLockActive[msg.sender] = true;
    }
    
    function extendTimeLock(uint256 additionalTime) public {
        if(timeLockActive[msg.sender]) {
            // Vulnerable: Uses block.timestamp which can be manipulated by miners
            if(now >= timeLockStart[msg.sender] + timeLockDuration[msg.sender]) {
                timeLockDuration[msg.sender] = additionalTime;
                timeLockStart[msg.sender] = now;
            }
        }
    }
    
    function emergencyUnlockWithDelay(address token, uint256 tokens) public {
        // Multi-transaction vulnerability: requires initializeTimeLock first, then this
        if(timeLockActive[msg.sender]) {
            // Vulnerable timestamp check - miners can manipulate this
            if(now >= timeLockStart[msg.sender] + (timeLockDuration[msg.sender] / 2)) {
                timeLockActive[msg.sender] = false;
                if(dep_token[msg.sender][token] >= tokens) {
                    dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token], tokens);
                    Token(token).transfer(msg.sender, tokens);
                }
            }
        }
    }
    // === END FALLBACK INJECTION ===

}
/*
 * ===== SmartInject Injection Details =====
 * Function      : timedWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where the withdrawal timing can be manipulated by miners. The vulnerability is stateful and multi-transaction because: 1) Users must first call requestWithdrawal() to set a timestamp, 2) They must wait for the delay period, 3) They call executeWithdrawal() or timedWithdrawal() to complete the withdrawal. The state (withdrawal_timestamps) persists between transactions, and miners can manipulate the 'now' timestamp to either prevent or allow withdrawals prematurely. This creates a multi-step exploit where attackers need to coordinate timing across multiple transactions.
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
mapping (address => uint256) public withdrawal_requests;
mapping (address => uint256) public withdrawal_amounts;
mapping (address => uint256) public withdrawal_timestamps;
uint256 public withdrawal_delay = 1 hours;

function requestWithdrawal(address token, uint256 amount) public {
    require(dep_token[msg.sender][token] >= amount, "Insufficient balance");
    withdrawal_requests[msg.sender] = withdrawal_requests[msg.sender] + amount;
    withdrawal_amounts[msg.sender] = amount;
    withdrawal_timestamps[msg.sender] = now;
}

function executeWithdrawal(address token) public {
    require(withdrawal_requests[msg.sender] > 0, "No pending withdrawal");
    require(now >= withdrawal_timestamps[msg.sender] + withdrawal_delay, "Withdrawal delay not met");
    
    uint256 amount = withdrawal_amounts[msg.sender];
    withdrawal_requests[msg.sender] = 0;
    withdrawal_amounts[msg.sender] = 0;
    withdrawal_timestamps[msg.sender] = 0;
    
    dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token], amount);
    Token(token).transfer(msg.sender, amount);
}

function timedWithdrawal(address token, uint256 amount) public {
    require(dep_token[msg.sender][token] >= amount, "Insufficient balance");
    
    if (now > withdrawal_timestamps[msg.sender] + withdrawal_delay) {
        dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token], amount);
        Token(token).transfer(msg.sender, amount);
    }
}
    // === END FALLBACK INJECTION ===

}
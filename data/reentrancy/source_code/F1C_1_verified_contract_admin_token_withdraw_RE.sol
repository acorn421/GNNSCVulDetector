/*
 * ===== SmartInject Injection Details =====
 * Function      : admin_token_withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering the external call and state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 (Setup)**: Admin deposits tokens using the `transfer` function to accumulate a balance in `dep_token[admin][token]` (e.g., 1000 tokens)
 * 
 * 2. **Transaction 2 (Exploit)**: Admin calls `admin_token_withdraw` with a malicious contract as the `to` parameter that implements a token receiver callback
 * 
 * 3. **Reentrancy Chain**: During the `Token(token).transfer(to, tokens)` call, the malicious contract's callback function repeatedly calls back into `admin_token_withdraw` before the original state update completes
 * 
 * 4. **State Exploitation**: Each reentrant call sees the same `dep_token[msg.sender][token]` balance because the state update happens after the external call, allowing withdrawal of the same tokens multiple times
 * 
 * **Why Multi-Transaction is Required:**
 * - The admin must first accumulate token balance through separate deposit transactions
 * - The exploit requires a malicious contract to be deployed and set as the recipient 
 * - The reentrancy only works because previous transactions established the dep_token state
 * - Each reentrant call depends on the persistent state from earlier transactions
 * 
 * **Realistic Exploitation:**
 * - Admin deposits 1000 tokens (Transaction 1)
 * - Admin withdraws 500 tokens to malicious contract (Transaction 2)  
 * - Malicious contract reenters during transfer, withdrawing another 500 tokens
 * - Process repeats until contract is drained
 * - Original state update finally executes, but damage is done
 * 
 * This creates a classic reentrancy vulnerability where the checks-effects-interactions pattern is violated, enabling stateful exploitation across multiple transactions.
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // VULNERABILITY: External call before state update enables reentrancy
                // If 'to' is a contract, it can call back into this function
                Token(token).transfer(to, tokens);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token] , tokens) ;   
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
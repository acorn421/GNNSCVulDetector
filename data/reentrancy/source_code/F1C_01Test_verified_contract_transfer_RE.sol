/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism after state updates but before the actual token transfer. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added a low-level `call()` to the token contract with an `onTokenDeposit` callback
 * 2. The callback is executed AFTER updating the `dep_token` state but BEFORE the actual `transferFrom`
 * 3. This creates a window where the state shows tokens are deposited but they haven't been transferred yet
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious token contract that implements `onTokenDeposit` callback
 * 2. **Transaction 2 (Initial Deposit)**: Attacker calls `transfer()` with their malicious token:
 *    - `dep_token[attacker][malicious_token]` is updated to show deposit
 *    - Callback `onTokenDeposit` is triggered, allowing the malicious token to re-enter
 *    - During re-entrance, the malicious token can call other contract functions that rely on the `dep_token` state
 * 3. **Transaction 3+ (Exploitation)**: The attacker can use withdrawal functions or other contract methods that check `dep_token` balances, exploiting the inconsistent state where balances are recorded but tokens weren't actually transferred
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires deploying a malicious token contract first (Transaction 1)
 * - The actual exploitation happens through the callback during deposit (Transaction 2)
 * - Maximum damage occurs when the attacker uses the manipulated `dep_token` state in subsequent transactions (Transaction 3+)
 * - The stateful nature means the corrupted `dep_token` balances persist across transactions, enabling continued exploitation
 * 
 * **State Persistence Factor:**
 * The `dep_token` mapping maintains corrupted state across transactions, where recorded balances don't match actual token transfers, enabling long-term exploitation across multiple function calls.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify the token contract about the deposit with callback
            if(token.call(bytes4(keccak256("onTokenDeposit(address,uint256)")), msg.sender, tokens))
            {
                // Callback successful - additional processing if needed
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}
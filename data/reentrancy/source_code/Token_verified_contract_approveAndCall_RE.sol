/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Modification Before External Call**: The function updates both `allowed` mapping and `dep_token` mapping before making the external call to `_spender`. This violates the Checks-Effects-Interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User calls `approveAndCall(maliciousContract, 1000, calldata)` 
 *    - The function updates `allowed[user][maliciousContract] = 1000` and `dep_token[user][contract] += 1000`
 *    - External call to `maliciousContract` is made with `_extraData`
 *    - **Reentrant Call**: The malicious contract's fallback function calls back into the contract (e.g., `token_withdraw` or other functions)
 *    - **Transaction 2**: During reentrancy, the malicious contract can exploit the inconsistent state where approvals are set but the original transaction hasn't completed
 *    - The malicious contract can call `transferFrom` or other functions that depend on the `allowed` mapping before the original transaction completes
 * 
 * 3. **Stateful Vulnerability**: The `dep_token` mapping maintains state across transactions, allowing an attacker to accumulate approvals and manipulate balances through multiple calls. The vulnerability requires the state to be built up over multiple transactions.
 * 
 * 4. **Realistic Exploitation**: An attacker could:
 *    - Set up a malicious contract that implements a fallback function
 *    - Call `approveAndCall` multiple times to build up state in `dep_token`
 *    - During each external call, reenter the contract to exploit the temporary state inconsistency
 *    - Extract tokens or manipulate balances before the original transactions complete
 * 
 * The vulnerability is subtle because it appears to implement legitimate approval-and-call functionality while creating a window for reentrancy attacks that depend on accumulated state changes.
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
    // Declare dep_token as a mapping inside Token to fix errors
    mapping (address => mapping(address => uint256)) public dep_token;
    // Declare safeAdd and safeSub functions inside Token
    function safeAdd(uint crtbal, uint depbal) public returns (uint) {
        uint totalbal = crtbal + depbal;
        return totalbal;
    }
    function safeSub(uint crtbal, uint depbal) public returns (uint) {
        uint totalbal = crtbal - depbal;
        return totalbal;
    }
    function transfer(address _to, uint256 _value) public returns (bool success);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData) public returns (bool success) {
        // Update approval state first
        allowed[msg.sender][_spender] = _value;
        // Track pending approvals for enhanced functionality
        dep_token[msg.sender][address(this)] = safeAdd(dep_token[msg.sender][address(this)], _value);
        // Make external call to spender with extra data (VULNERABLE: state update before external call)
        bool callSuccess = _spender.call(_extraData);
        // Only complete the approval process if the call was successful
        if (callSuccess) {
            // Emit approval event (simulated)
            return true;
        } else {
            // Revert the state changes if call failed
            allowed[msg.sender][_spender] = 0;
            dep_token[msg.sender][address(this)] = safeSub(dep_token[msg.sender][address(this)], _value);
            return false;
        }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
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

 
    constructor() public
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
}
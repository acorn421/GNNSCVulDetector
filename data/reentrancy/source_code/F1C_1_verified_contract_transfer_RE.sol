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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token contract using a low-level call() that invokes an onDepositReceived callback. The vulnerability is stateful because:
 * 
 * 1. **State Accumulation Phase**: Users must first build up significant balances in dep_token through multiple legitimate deposit transactions over time.
 * 
 * 2. **Exploitation Setup**: The attacker deploys a malicious token contract that implements the onDepositReceived callback function, which re-enters the transfer function when called.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1-N: User makes multiple legitimate deposits, building up balance in dep_token[user][token]
 *    - Transaction N+1: Attacker calls transfer() with malicious token contract
 *    - During the callback, the malicious contract re-enters transfer() multiple times before the original transferFrom completes
 *    - Each re-entry updates dep_token but the actual token transfer happens after all callbacks
 *    - This creates a state inconsistency where dep_token shows multiple deposits but only one actual transfer occurs
 * 
 * 4. **State Persistence**: The vulnerability relies on the persistent state in dep_token mapping that accumulates across transactions, and the fact that the callback happens after state update but before the actual token transfer.
 * 
 * The vulnerability requires multiple transactions because:
 * - Users need previous transactions to build up exploitable balances
 * - The exploit itself requires the callback to trigger multiple re-entries
 * - The state inconsistency only becomes profitable when there are accumulated deposits from previous transactions
 * 
 * This creates a realistic vulnerability pattern where the attack surface grows with accumulated state from legitimate usage over time.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Call external contract for deposit notification - potential reentrancy vector
            if(token.call(bytes4(keccak256("onDepositReceived(address,uint256)")), msg.sender, tokens)) {
                // Callback executed, state already updated above
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
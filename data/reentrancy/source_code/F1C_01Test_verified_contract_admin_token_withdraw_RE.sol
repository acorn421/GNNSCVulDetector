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
 * **Specific Changes Made:**
 * 1. **Reordered Operations**: Moved the external call `Token(token).transfer(to, tokens)` BEFORE the state update `dep_token[msg.sender][token] = safeSub(...)` 
 * 2. **Preserved Function Logic**: All original functionality remains intact - admin check, balance validation, and withdrawal operations
 * 3. **Maintained Signature**: Function parameters, visibility, and return behavior unchanged
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Admin deposits tokens using `transfer()` function, establishing initial state in `dep_token[adminaddr][token]`
 * 2. **Transaction 2**: Admin calls `admin_token_withdraw()` with a malicious token contract address
 * 3. **During Transaction 2**: The malicious token's `transfer()` function re-enters `admin_token_withdraw()` BEFORE the balance is updated
 * 4. **Transaction 3+**: Each reentrant call can withdraw the full balance again since `dep_token[adminaddr][token]` hasn't been decremented yet
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Accumulation**: The vulnerability depends on previously established deposit balances from earlier transactions
 * - **Persistent State**: The `dep_token` mapping maintains state between transactions that the attack leverages
 * - **Sequential Dependency**: The exploit requires the admin to first have deposited tokens (Transaction 1), then attempt withdrawal (Transaction 2+)
 * - **Stateful Reentrancy**: Unlike simple reentrancy, this exploits the contract's deposit tracking system across multiple calls
 * 
 * **Exploitation Flow:**
 * 1. **Setup Phase**: Admin deposits 1000 tokens via `transfer()` → `dep_token[adminaddr][token] = 1000`
 * 2. **Attack Phase**: Admin calls `admin_token_withdraw(maliciousToken, attacker, 1000)`
 * 3. **Reentrancy**: Malicious token's `transfer()` re-enters before balance update
 * 4. **Drain**: Multiple reentrant calls can each withdraw 1000 tokens since balance check still passes
 * 5. **State Corruption**: Final state update occurs after all reentrant calls complete
 * 
 * This creates a realistic vulnerability where the contract's deposit tracking system can be exploited through carefully timed external calls that manipulate the order of operations across multiple transactions.
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // State update moved AFTER external call - creates reentrancy vulnerability
                Token(token).transfer(to, tokens);
                dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token] , tokens);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
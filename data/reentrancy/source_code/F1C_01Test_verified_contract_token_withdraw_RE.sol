/*
 * ===== SmartInject Injection Details =====
 * Function      : token_withdraw
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Modification Before External Call**: The function updates `dep_token[msg.sender][token]` state BEFORE making the external Token.transfer() call, creating the classic reentrancy vulnerability pattern.
 * 
 * 2. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Admin deposits tokens via `transfer()` function, setting up initial `dep_token` state
 *    - **Transaction 2**: Admin calls `token_withdraw()` which updates state and makes external call
 *    - **During External Call**: If the token contract or recipient has a callback mechanism, it can re-enter and call other functions that read/modify the `dep_token` state while the withdrawal is still in progress
 *    - **Transaction 3+**: Subsequent calls can exploit the inconsistent state where tokens have been debited but transfer might fail or be manipulated
 * 
 * 3. **Stateful Nature**: The vulnerability requires accumulated state from previous transactions (token deposits) and creates persistent state changes that can be exploited across multiple function calls.
 * 
 * 4. **Reentrancy Vector**: The `Token(token).transfer(to, tokens)` call can potentially trigger callbacks in malicious token contracts or recipient contracts, allowing them to re-enter the contract while the state is in an inconsistent state.
 * 
 * 5. **Multi-Transaction Requirement**: The exploit requires:
 *    - Prior token deposits (Transaction 1)
 *    - Initial withdraw call (Transaction 2) 
 *    - Reentrancy exploitation during external call (still part of Transaction 2 but enables future exploitation)
 *    - Potential follow-up transactions to fully exploit the state inconsistency
 * 
 * The vulnerability is subtle and realistic, as it follows the common pattern of state-change-before-external-call that has been seen in many real-world DeFi exploits.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Record pending withdrawal - this state persists between transactions
            dep_token[msg.sender][token] = safeSub(dep_token[msg.sender][token] , tokens) ;   
            
            // External call that can trigger reentrancy - state has already been updated
            Token(token).transfer(to, tokens);
            
            // Additional state modification that creates vulnerability window
            // This allows accumulated state changes across multiple transactions
            if(dep_token[msg.sender][token] == 0) {
                // Reset mechanism that can be exploited across multiple calls
                dep_token[msg.sender][token] = 0;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
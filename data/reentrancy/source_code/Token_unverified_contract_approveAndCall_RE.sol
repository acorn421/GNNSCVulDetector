/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Variables**: Created mappings to track pending approvals, amounts, and nonces that persist between transactions
 * 2. **Two-Stage Approval Process**: Split the approval into two stages requiring separate transactions
 * 3. **External Call Before State Update**: Placed the external call to _spender before cleaning up the pending state
 * 4. **Vulnerable State Window**: Created a window where pending approval state can be manipulated during reentrancy
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: User calls approveAndCall() 
 * - Sets pendingApprovals[user][spender] = true
 * - Stores approvalAmounts[user][spender] = _value
 * - Increments approvalNonce[user]
 * - Returns true (approval marked as pending)
 * 
 * **Transaction 2**: User calls approveAndCall() again (or attacker triggers it)
 * - Detects pending approval exists
 * - Makes external call to _spender.receiveApproval()
 * - During this call, _spender can re-enter approveAndCall()
 * - Re-entrancy can exploit the inconsistent state (pending=true, but external call in progress)
 * - Multiple approvals can be processed using the same pending state
 * - State cleanup happens after external call, creating exploitation window
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability relies on pendingApprovals state persisting between transactions
 * 2. **Staged Processing**: The two-stage approval process requires separate transactions to set up and exploit
 * 3. **Accumulated State**: The approvalNonce and pending mappings accumulate state across multiple calls
 * 4. **Reentrancy Window**: The external call creates a reentrancy window that can only be exploited after the pending state is established in a previous transaction
 * 
 * **Attack Vector**: A malicious spender contract can implement receiveApproval() to re-enter approveAndCall(), potentially processing multiple approvals or manipulating the approval amounts while the pending state is inconsistent. The attack requires establishing the pending state in one transaction and exploiting it in subsequent transactions through reentrancy during the external call.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => mapping(address => bool)) public pendingApprovals;
mapping(address => mapping(address => uint256)) public approvalAmounts;
mapping(address => uint256) public approvalNonce;

function approveAndCall(address _spender, uint256 _value, bytes memory _extraData) public returns (bool success) {
    // Stage 1: Mark approval as pending (persists between transactions)
    if (!pendingApprovals[msg.sender][_spender]) {
        pendingApprovals[msg.sender][_spender] = true;
        approvalAmounts[msg.sender][_spender] = _value;
        approvalNonce[msg.sender] = approvalNonce[msg.sender] + 1;
        return true;
    }
    
    // Stage 2: Process pending approval with external call BEFORE state update
    if (pendingApprovals[msg.sender][_spender]) {
        uint256 pendingAmount = approvalAmounts[msg.sender][_spender];
        
        // VULNERABILITY: External call before state cleanup
        // This allows reentrancy to exploit the pending state
        (bool callSuccess,) = _spender.call(abi.encodeWithSignature(
            "receiveApproval(address,uint256,address,bytes)",
            msg.sender,
            pendingAmount,
            address(this),
            _extraData
        ));
        
        // State cleanup happens AFTER external call (vulnerable window)
        if (callSuccess) {
            allowed[msg.sender][_spender] = pendingAmount;
            pendingApprovals[msg.sender][_spender] = false;
            approvalAmounts[msg.sender][_spender] = 0;
            return true;
        }
    }
    
    return false;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}
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
}
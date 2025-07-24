/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating balances. This creates a classic reentrancy pattern where:
 * 
 * 1. **SPECIFIC CHANGES MADE:**
 *    - Added an external call `TokenRecipient(_to).tokenReceived(msg.sender, _value, "")` after the require checks but before balance updates
 *    - The call is only made if `_to` has code (is a contract), making it a realistic token notification pattern
 *    - State updates (balance modifications) remain after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * 2. **MULTI-TRANSACTION EXPLOITATION SEQUENCE:**
 *    - **Transaction 1**: Deploy malicious recipient contract that implements `tokenReceived` callback
 *    - **Transaction 2**: Victim calls `transfer()` to the malicious contract
 *    - **Reentrancy Chain**: During the external call, the malicious contract can call `transfer()` again before the original balance update occurs
 *    - Each reentrant call sees the same pre-update balance state, allowing multiple withdrawals from the same balance
 * 
 * 3. **WHY MULTI-TRANSACTION IS REQUIRED:**
 *    - The vulnerability requires the malicious recipient contract to be deployed in a separate transaction first
 *    - The exploitation depends on the accumulated state from the initial transfer call (the unchanged balance)
 *    - Multiple reentrant calls drain the sender's balance progressively, with each call depending on the persistent state from previous calls
 *    - The attack cannot be performed in a single atomic transaction because it requires the external contract to be pre-deployed and the reentrancy to occur during the callback execution
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world ERC20 token notification patterns while being exploitable only through multiple transactions and state accumulation.
 */
pragma solidity ^0.4.16;

contract TokenRecipient {
    function tokenReceived(address _from, uint256 _value, bytes _extraData) public;
}

contract ERC20token{
    uint256 public totalSupply;
    string public name;
    uint8 public decimals;
    string public symbol;
    address public admin;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    mapping (address => bool) public frozenAccount;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
    function ERC20token(uint256 _initialAmount, string _tokenName, uint8 _decimalUnits, string _tokenSymbol) public {
        totalSupply = _initialAmount * 10 ** uint256(_decimalUnits);
        balances[msg.sender] = totalSupply;
        admin = msg.sender;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(!frozenAccount[msg.sender]);
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABLE: External call to recipient before state updates
        // This allows token recipient contracts to implement custom logic
        uint256 length;
        assembly {
            length := extcodesize(_to)
        }
        if(length > 0) {
            TokenRecipient(_to).tokenReceived(msg.sender, _value, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(!frozenAccount[msg.sender]);
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
    
     function freeze(address _target,bool _freeze) public returns (bool) {
        require(msg.sender == admin);
        // require(_target != address(0));
        // require(_target != admin);
        frozenAccount[_target] = _freeze;
        return true;
    }
    
    // function cgadmin(address _newadmin) public returns (bool){
    //      require(msg.sender == admin);
    // }
    
    function approve(address _spender, uint256 _value) public returns (bool success)
    {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}

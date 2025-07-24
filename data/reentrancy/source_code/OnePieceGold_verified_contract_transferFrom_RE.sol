/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability violates the Checks-Effects-Interactions pattern by placing the external call (recipient notification) after checks but before effects (state updates).
 * 
 * **Specific Changes Made:**
 * 1. Added recipient notification callback using low-level call() before state updates
 * 2. Moved the external call to occur between validation checks and state modifications
 * 3. Made the callback conditional on recipient being a contract (code.length > 0)
 * 4. Continued execution regardless of callback success to maintain functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls transferFrom with a malicious recipient contract
 * 2. **During callback**: Malicious contract calls transferFrom again with same parameters
 * 3. **Vulnerability**: State hasn't been updated yet, so balance/allowance checks pass again
 * 4. **Result**: Double spending occurs across the nested calls
 * 5. **Transaction 2**: Attacker can repeat the process to drain remaining tokens
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to have a contract deployed that implements the callback
 * - The exploitation depends on the persistent state of balances and allowances between calls
 * - The attack requires setting up allowances in previous transactions
 * - Full exploitation requires multiple transferFrom calls to drain significant amounts
 * - The accumulated effect of multiple successful transfers creates the damage
 * 
 * **Stateful Nature:**
 * - Balances and allowances are persistent state that carry between transactions
 * - Each successful exploit modifies the state for subsequent calls
 * - The vulnerability depends on the contract's stored state remaining vulnerable between transactions
 * - Multiple calls can compound the effect by repeatedly exploiting the same allowance
 */
pragma solidity ^0.4.11;
 
contract OnePieceGold {
    string public symbol = "";
    string public name = "";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 0;
    address owner = 0;
    bool setupDone = false;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 
    mapping(address => uint256) balances;
 
    mapping(address => mapping (address => uint256)) allowed;
 
    // Updated to constructor syntax
    constructor(address adr) public {
        owner = adr;        
    }
    
    function SetupToken(string tokenName, string tokenSymbol, uint256 tokenSupply) public
    {
        if (msg.sender == owner && setupDone == false)
        {
            symbol = tokenSymbol;
            name = tokenName;
            _totalSupply = tokenSupply * 1000000000000000000;
            balances[owner] = _totalSupply;
            setupDone = true;
        }
    }
 
    // Removed shadowed parameter name
    function totalSupply() public constant returns (uint256) {        
        return _totalSupply;
    }
 
    function balanceOf(address _owner) public constant returns (uint256) {
        return balances[_owner];
    }
 
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            emit Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) public returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient before state updates - introduces reentrancy vulnerability
            uint size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                // External call to recipient contract allowing callback
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _amount);
                // Continue execution regardless of callback success
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            emit Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}

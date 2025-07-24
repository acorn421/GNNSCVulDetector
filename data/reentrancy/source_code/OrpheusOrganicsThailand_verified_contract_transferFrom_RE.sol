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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection creates a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by:
 * 
 * 1. **External Call Addition**: Added a callback mechanism that calls `onTokenReceived` on the recipient address if it's a contract, placed strategically between balance updates and allowance updates.
 * 
 * 2. **State Inconsistency Window**: The external call occurs after balances are updated but before the allowance is decremented, creating a window where state is inconsistent across transactions.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker sets up initial allowance and deploys malicious contract
 *    - **Transaction 2**: Attacker calls transferFrom with malicious contract as _to
 *    - **During Transaction 2**: The external call triggers reentrancy in the malicious contract
 *    - **Reentrant Call**: The malicious contract can call transferFrom again while allowance hasn't been decremented yet
 *    - **State Persistence**: The vulnerability exploits the fact that allowance state persists between the initial call and reentrant call
 * 
 * 4. **Multi-Transaction Dependency**: The attack requires:
 *    - Prior transaction to set up allowance approval
 *    - Multiple coordinated calls to exploit the state inconsistency
 *    - Cannot be exploited atomically in a single transaction due to the need for external contract deployment and allowance setup
 * 
 * 5. **Realistic Implementation**: The callback pattern is common in modern token contracts (similar to ERC777 or ERC1363), making this vulnerability realistic and subtle.
 * 
 * **Exploitation Sequence**:
 * 1. Attacker gets approval to spend tokens from victim
 * 2. Attacker deploys malicious contract that implements onTokenReceived
 * 3. Attacker calls transferFrom with malicious contract as recipient
 * 4. During the external call, malicious contract reenters transferFrom
 * 5. Second call succeeds because allowance hasn't been decremented yet
 * 6. Process repeats until allowance or balance is exhausted
 * 
 * The vulnerability is only exploitable through multiple transactions and requires persistent state manipulation across calls.
 */
pragma solidity ^0.4.11;
contract OrpheusOrganicsThailand {
    
    uint public constant _totalSupply = 5000000000000000000000000;
    
    string public constant symbol = "OOT";
    string public constant name = "Orpheus Organics Thailand";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    function OrpheusOrganicsThailand() public {
        balances[msg.sender] = _totalSupply;
    }
    
    function totalSupply() public constant returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner]; 
    }
    
    function transfer (address _to, uint256 _value) public returns (bool success) {
        require(    
            balances[msg.sender] >= _value
            && _value > 0 
        );
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before updating allowance (vulnerability)
        if (isContract(_to)) {
            // Notify recipient contract about the transfer
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
            // Continue execution regardless of callback success
        }
        
        // Update allowance after external call (creates reentrancy window)
        allowed[_from][msg.sender] -= _value;
        
        emit Transfer(_from, _to, _value);
        return true;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 

    // Helper function to detect if an address is a contract
    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Specific Changes Made:**
 *    - Added an external call to the recipient address (`_to.call()`) before state updates
 *    - The call invokes `onTokenReceived(address,uint256)` if the recipient is a contract
 *    - State modifications (balance updates) occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 *    - Used low-level `call()` which doesn't propagate failures, making the vulnerability subtle
 * 
 * 2. **Multi-Transaction Exploitation Scenario:**
 *    - **Transaction 1**: Attacker deploys a malicious contract that implements `onTokenReceived()`
 *    - **Transaction 2**: Attacker calls `transfer()` to send tokens to their malicious contract
 *    - **During Transaction 2**: The malicious contract's `onTokenReceived()` callback is triggered BEFORE the sender's balance is updated
 *    - **Reentrancy Attack**: The callback can call `transfer()` again, creating nested calls that can drain the sender's balance
 *    - **State Accumulation**: Each reentrant call checks the original balance (not yet updated) and transfers more tokens
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The attacker must first deploy the malicious contract (Transaction 1)
 *    - The vulnerability only triggers when tokens are transferred TO a contract address (Transaction 2)
 *    - The malicious contract's code must be persistent on-chain to execute the callback
 *    - The attack relies on the accumulated state changes across multiple nested function calls within the exploitation transaction
 *    - Without the pre-deployed malicious contract, the vulnerability cannot be exploited
 * 
 * 4. **Stateful Nature:**
 *    - The `balances` mapping persists between transactions
 *    - The malicious contract's bytecode persists on-chain
 *    - Each reentrant call operates on the same persistent balance state
 *    - The vulnerability accumulates effects across multiple nested calls, all operating on the same stateful storage
 * 
 * This creates a realistic reentrancy vulnerability that requires careful setup across multiple transactions and exploits the persistent state nature of blockchain storage.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state update - introduces reentrancy vulnerability
        // The check for contract is replaced for pre-0.8.0 syntax (can't use .code)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed [_from][msg.sender] -= _value;
        Transfer (_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 
}

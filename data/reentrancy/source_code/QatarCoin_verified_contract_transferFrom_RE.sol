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
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `transferPendingAmounts` mapping to track pending transfer amounts across transactions
 * 2. **External Call Before State Update**: Added a call to recipient contract's `onTokenReceive` function before updating balances
 * 3. **State Persistence**: The `transferPendingAmounts` state persists between transactions, enabling multi-transaction exploitation
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker calls `transferFrom` with victim's tokens, triggering the external call to attacker's contract
 * - **During Callback**: The attacker's `onTokenReceive` function calls `transferFrom` again while `transferPendingAmounts` still shows pending amounts but `balances` haven't been updated yet
 * - **Transaction 2**: Second call processes using the same allowance/balance checks, effectively allowing double-spending
 * - **State Accumulation**: The `transferPendingAmounts` accumulates across calls, but balance updates happen independently
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call callback to trigger additional `transferFrom` calls
 * - State persistence (`transferPendingAmounts`) enables exploitation across multiple function invocations
 * - The attacker needs to deploy a malicious contract that responds to `onTokenReceive` - this requires a separate transaction
 * - The exploitation depends on the accumulated state from previous partial executions
 * 
 * This creates a realistic reentrancy vulnerability where the external call enables state manipulation before critical updates are completed, requiring multiple transactions to fully exploit the accumulated state inconsistencies.
 */
pragma solidity ^0.4.11;

contract QatarCoin{
    
    uint public constant _totalsupply = 95000000;
    
    string public constant symbol = "QTA";
    string public constant name = "Qatar Coin";
    uint8 public constant decimls = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) transferPendingAmounts;
    
    // Constructor function using old-style for ^0.4.11
    function QatarCoin() public {
       balances[msg.sender] = _totalsupply;
    }

    function totalSupply() public constant returns (uint256) {
        return _totalsupply;
    }
    
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
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
        
        // Track transfer initiation for compliance notification
        transferPendingAmounts[_from] += _value;
        
        // Notify recipient if it's a contract (external call before state update)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call that can trigger reentrancy
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceive(address,uint256)")), _from, _value);
        }
        
        // State updates happen after external call - vulnerable to reentrancy
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][msg.sender] -= _value;
        
        // Clear pending amount only after successful transfer
        transferPendingAmounts[_from] -= _value;
        
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

}

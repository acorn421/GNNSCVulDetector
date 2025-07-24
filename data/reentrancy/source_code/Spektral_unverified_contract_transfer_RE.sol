/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that notifies recipient contracts about incoming transfers. The vulnerability is exploitable through multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` with `onTokenReceived` callback after balance updates
 * 2. Inserted the callback between balance modifications and event emission
 * 3. Added `isContract()` helper function to determine if recipient is a contract
 * 4. The callback executes regardless of success/failure, continuing normal execution
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onTokenReceived`
 * 2. **Transaction 2**: Victim transfers tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered
 * 4. **Reentrancy Attack**: The callback can call back into the `transfer` function or other contract functions while the original transfer is still executing
 * 5. **State Manipulation**: The attacker can manipulate balances or perform additional transfers before the original Transfer event is emitted
 * 
 * **Why Multi-Transaction Exploitation:**
 * - The attacker must first deploy their malicious contract (Transaction 1)
 * - The vulnerability is only triggered when tokens are transferred TO a contract address (Transaction 2)
 * - The reentrancy occurs during the callback execution, allowing the attacker to manipulate state that persists between the callback and the original function completion
 * - Multiple transfers to the same malicious contract can compound the vulnerability effects
 * - The attacker can build up state across multiple transfer operations, each triggering the callback
 * 
 * **Realistic Nature:**
 * - Token recipient notification is a legitimate feature in many modern token contracts
 * - The callback mechanism appears as intended functionality for DeFi integrations
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - The external call placement after balance updates but before event emission is a common pattern that creates the vulnerability window
 */
pragma solidity ^0.4.24;

contract Spektral {
    string public name;
    string public symbol;
    uint256 public totalSupply;
    uint8 public decimals;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
        name = "Spektral";
        symbol = "SPK";
        decimals = 18;
        totalSupply = 600000000000 * 10**18;
        balances[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient contract about the transfer
            // This callback allows recipient to react to incoming tokens
            if (isContract(_to)) {
                // External call before final state cleanup - vulnerable to reentrancy
                (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
                // Continue execution regardless of callback result
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Transfer(msg.sender, _to, _value);
            return true;
        }else{
            return false;
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is a contract
    function isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            emit Transfer(_from, _to, _value);
            return true;
        }else{
            return false;
        }
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
}
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
 * **STATEFUL, MULTI-TRANSACTION Reentrancy Vulnerability Injection**
 * 
 * **Specific Changes Made:**
 * 1. **Added external call to recipient contract**: Inserted `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value))` after updating the recipient's balance but before updating the sender's balance and allowance.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call now occurs in the middle of state updates, creating a reentrancy window where:
 *    - Recipient balance has been increased
 *    - Sender balance has NOT been decreased yet
 *    - Allowance has NOT been decreased yet
 * 
 * 3. **Created Contract Code Check**: Added `_to.code.length > 0` to only call contracts, making the vulnerability realistic and targeted.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker creates a malicious contract that implements `onTokenReceived`
 * - Victim approves the attacker's EOA to spend tokens via `approve(attackerEOA, largeAmount)`
 * 
 * **Transaction 2 - Initial Exploitation:**
 * - Attacker EOA calls `transferFrom(victim, maliciousContract, amount)`
 * - When `maliciousContract.onTokenReceived` is called:
 *   - Malicious contract's balance has been increased
 *   - Victim's balance has NOT been decreased yet
 *   - Allowance has NOT been decreased yet
 * - Malicious contract can now call `transferFrom` again with the same allowance
 * 
 * **Transaction 3+ - Drain Phase:**
 * - During the reentrancy callback, malicious contract can:
 *   - Call `transferFrom` repeatedly using the same allowance
 *   - Transfer tokens to multiple attacker-controlled addresses
 *   - Drain the victim's balance beyond the original intended amount
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Persistence**: The vulnerability exploits the persistent state of balances and allowances across transactions
 * 2. **Setup Required**: Victim must first approve the attacker in a separate transaction
 * 3. **Progressive Exploitation**: Each reentrant call can transfer more tokens, requiring multiple nested calls within the transaction
 * 4. **Allowance Dependency**: The exploit depends on the allowance being set in a prior transaction and not being properly decremented during reentrancy
 * 
 * **Realistic Integration**: This vulnerability mimics real-world patterns where tokens implement recipient notification hooks for better UX, making it a subtle and believable security flaw that could exist in production code.
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
            emit Transfer(msg.sender, _to, _value);
            return true;
        }else{
            return false;
        }
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Recipient notification callback - vulnerable to reentrancy
            uint256 size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                // Note: "abi.encodeWithSignature" is not available in 0.4.24, use manually
                bytes4 sig = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
                require(_to.call(sig, _from, msg.sender, _value)); // Ignore call result to maintain compatibility
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to recipient contract using `_to.call(payload)` 
 * - Implemented a token receiver notification mechanism via `onTokenReceived(address,uint256)`
 * - External call occurs AFTER state updates (balances modified)
 * - No reentrancy guards or mutex protection
 * - Call continues execution regardless of success/failure
 * 
 * **2. Multi-Transaction Exploitation Sequence:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract with `onTokenReceived` function
 * - Attacker obtains some tokens to initiate the attack
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transfer(maliciousContract, amount)`
 * - Function updates balances: `balances[attacker] -= amount`, `balances[maliciousContract] += amount`
 * - Function calls `maliciousContract.onTokenReceived(attacker, amount)`
 * - Inside callback: malicious contract calls `transfer(attacker, amount)` again
 * - Second transfer sees updated balances from first transfer
 * - This creates a reentrancy where state from Transaction 2 affects nested calls
 * 
 * **Transaction 3+ (Exploitation):**
 * - Through recursive calls within Transaction 2's callback, attacker can:
 *   - Drain more tokens than they originally owned
 *   - Manipulate balance states across multiple nested calls
 *   - Each nested call depends on state changes from previous calls in the sequence
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Persistence:** The vulnerability exploits persistent storage state (`balances` mapping) that survives between function calls and transactions.
 * 
 * **Cumulative Effect:** Each call in the sequence depends on balance changes from previous calls. The attack requires:
 * - Initial state setup (Transaction 1)
 * - State modification triggering callbacks (Transaction 2)
 * - Nested state exploitation during callbacks (within Transaction 2, but conceptually separate execution contexts)
 * 
 * **Cross-Call Dependencies:** The vulnerability cannot be exploited in a single atomic transaction because:
 * - It requires the external call to trigger additional transfer calls
 * - Each subsequent call depends on the state changes from previous calls
 * - The attack leverages the fact that external calls can re-enter the contract with modified state
 * 
 * **Realistic Integration:** This pattern mimics real-world token standards (like ERC777) where recipient notification is a legitimate feature, making the vulnerability subtle and realistic.
 * 
 * **Exploitation Impact:** An attacker can potentially drain the contract by transferring tokens to themselves multiple times during the callback execution, with each call seeing the updated balances from previous calls in the sequence.
 */
pragma solidity ^0.4.24;
contract EIP20Interface {
    uint256 public totalSupply;
    mapping (address => uint256) public balances;

    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract - VULNERABILITY INJECTION POINT
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            bytes memory payload = abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value);
            // Note: _to.call.value(0)(payload) is the pattern for low-level call in 0.4.x
            // Though the function could not recognize .call{value: 0}(payload) in 0.4.24
            // So we use .call(payload)
            // (bool callSuccess,) = _to.call(payload);   // Can't destructure returned values in 0.4.24.
            _to.call(payload);
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract ECT is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => mapping (address => uint256)) public allowed;
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

    constructor (
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        totalSupply = _initialAmount*10**uint256(_decimalUnits);     // Update total supply
        balances[msg.sender] = totalSupply;                          // Update total supply
        name = _tokenName;                                           // Set the name for display purposes
        decimals = _decimalUnits;                                    // Amount of decimals for display purposes
        symbol = _tokenSymbol;                                       // Set the symbol for display purposes
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}

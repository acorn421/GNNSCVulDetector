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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **Specific Changes Made:**
 *    - Added external call to recipient contract using `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _amount))`
 *    - Placed this call BEFORE state updates (balances and allowances)
 *    - Added contract existence check with `_to.code.length > 0`
 *    - Added require statement for realistic error handling
 * 
 * 2. **Multi-Transaction Exploitation Scenario:**
 *    - **Transaction 1:** Attacker calls `transferFrom()` with malicious recipient contract
 *    - **During reentrancy:** The external call executes while state is still unchanged (checks passed but effects not applied)
 *    - **Nested calls:** Malicious recipient can call `transferFrom()` again with same parameters
 *    - **Transaction 2+:** Multiple nested calls can drain more tokens than allowed since `allowed[_from][msg.sender]` hasn't been decremented yet
 *    - **State accumulation:** Each successful nested call processes the same allowance multiple times
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The vulnerability exploits the time window between checks and state updates
 *    - Multiple nested calls within the same transaction chain are needed to drain funds
 *    - The allowance system requires the attack to span multiple `transferFrom()` calls
 *    - State changes from earlier calls enable deeper exploitation in subsequent calls
 *    - The attacker needs to build up a chain of recursive calls to maximize token extraction
 * 
 * 4. **Stateful Nature:**
 *    - The allowance mapping persists between transactions
 *    - Each nested call sees the same unchanged allowance value
 *    - Balance checks pass multiple times before any state updates occur
 *    - The vulnerability requires accumulated state manipulation across the call chain
 * 
 * This creates a realistic ERC-20 integration pattern where tokens notify recipients, but introduces a critical reentrancy vulnerability that requires sophisticated multi-transaction exploitation.
 */
pragma solidity ^0.4.16;

contract ETH {
    string public constant symbol = "ETH";
    string public constant name = "ETH";
    uint8 public constant decimals = 6;
    uint256 _totalSupply = (10 ** 8) * (10 ** 6);

    address public owner;
 
    mapping(address => uint256) balances; 
    mapping(address => mapping (address => uint256)) allowed;
 
    function ETH() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
 
    function () public {
        revert();
    }

    function totalSupply() constant public returns (uint256) {
        return _totalSupply;
    }
     
    function balanceOf(address _owner) constant public returns (uint256 balance) {
        return balances[_owner];
    }
 
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        if (balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient before state updates to enable transfer hooks
            /* Solidity 0.4.16 does not support 'address.code.length'. Instead, use extcodesize. */
            uint256 size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                bool callSuccess = _to.call(
                    bytes4(keccak256("onTokenReceived(address,address,uint256)")),
                    _from, msg.sender, _amount
                );
                require(callSuccess);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

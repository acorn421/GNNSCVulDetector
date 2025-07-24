/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a `_to.call()` to notify the recipient contract before decrementing the allowance
 * 2. **Violation of Checks-Effects-Interactions**: The external call occurs after the initial require check but before the critical state update (`allowance[_from][msg.sender] -= _value`)
 * 3. **Realistic Functionality**: The call appears as a legitimate token transfer notification mechanism, common in modern ERC20 implementations
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Token owner approves attacker contract for 1000 tokens
 * - `allowance[owner][attacker] = 1000`
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(owner, attackerContract, 1000)`
 * - Flow: `require(_value <= allowance[owner][attacker])` ✓ (1000 <= 1000)
 * - External call triggers: `attackerContract.onTokenReceive(owner, 1000)`
 * - **REENTRANCY WINDOW**: During callback, allowance is still 1000 (not yet decremented)
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - Inside the callback, attacker calls `transferFrom(owner, attackerContract, 1000)` again
 * - Flow: `require(_value <= allowance[owner][attacker])` ✓ (1000 <= 1000) - STILL PASSES
 * - This can be repeated multiple times within the same callback
 * - Each call drains 1000 tokens while the allowance remains unchanged during the callback
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The allowance state persists between the initial approval (Transaction 1) and the attack (Transaction 2+)
 * 2. **Callback Chain**: The vulnerability requires the external call to trigger reentrancy, which cannot happen without the recipient being a contract
 * 3. **Accumulated Exploitation**: Each reentrant call within the callback effectively constitutes a separate logical transaction that exploits the persistent allowance state
 * 4. **No Single-Transaction Exploit**: The vulnerability cannot be exploited in isolation - it requires the pre-existing allowance state and the external call trigger
 * 
 * **Attack Result:**
 * - Attacker can drain multiple times the approved amount
 * - If approved for 1000 tokens, attacker can potentially drain 1000 tokens per reentrant call
 * - The allowance is only decremented once per original transaction, but tokens are transferred multiple times
 */
pragma solidity ^0.4.16;

contract RxPharma{
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function RxPharma() public {
        totalSupply = 50000000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Rx Pharma Token";
        symbol = "RXP";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient before state updates - creates reentrancy window
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceive(address,uint256)")), _from, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }

    // Helper function to check if address is contract (for pre-0.5.0 Solidity)
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}

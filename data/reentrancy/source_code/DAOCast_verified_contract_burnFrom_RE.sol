/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder's contract after validation but before state updates. This violates the Checks-Effects-Interactions pattern and enables multi-transaction exploitation through allowance manipulation.
 * 
 * **Specific Changes Made:**
 * 1. Added external call `tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION")` after the allowance check but before state updates
 * 2. The call only triggers when _from != msg.sender to maintain realistic behavior
 * 3. State variables (balanceOf, allowance, totalSupply) are updated after the external call, creating the vulnerability window
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * This vulnerability requires multiple transactions and persistent state to exploit:
 * 
 * **Transaction 1 (Setup):** 
 * - Victim approves attacker to burn tokens: `approve(attacker, 1000)`
 * - State: `allowance[victim][attacker] = 1000`, `balanceOf[victim] = 5000`
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `burnFrom(victim, 100)` 
 * - Function checks: `balanceOf[victim] >= 100` ✓, `allowance[victim][attacker] >= 100` ✓
 * - External call to `victim.receiveApproval(attacker, 100, contract, "BURN_NOTIFICATION")`
 * - Victim's malicious contract reenters with `burnFrom(victim, 100)` again
 * - Second call sees unchanged state: `allowance[victim][attacker] = 1000`, `balanceOf[victim] = 5000`
 * - Both calls pass validation but only after all reentrancy completes do state updates occur
 * - Result: 200 tokens burned but allowance only decremented once
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The allowance must be set in a prior transaction and persists between calls
 * 2. **Accumulated Effect**: Multiple reentrant calls within the same transaction accumulate effects that exceed the intended allowance
 * 3. **Cross-Call State**: The vulnerability depends on the allowance state being consistent across multiple function calls within the exploitation transaction
 * 4. **Setup Dependency**: The exploit requires pre-existing allowance state from earlier transactions
 * 
 * The vulnerability is stateful (depends on persistent allowance), multi-transaction (requires setup + exploitation), and realistic (notification callbacks are common in token contracts).
 */
pragma solidity ^0.4.19;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract DAOCast {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function DAOCast(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
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
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    // ======= Reentrancy Vulnerable burnFrom =======
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (_from != msg.sender) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}

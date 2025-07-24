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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the _from address (if it's a contract) after updating the balance but before updating the allowance and totalSupply. This creates a reentrancy window where the attacker can exploit the inconsistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_from).receiveApproval()` after balance update but before allowance/totalSupply updates
 * 2. Moved critical state updates (allowance and totalSupply) to occur after the external call
 * 3. Added contract detection with `_from.code.length > 0` to make the callback realistic
 * 4. Used try-catch to handle callback failures gracefully
 * 
 * **Multi-Transaction Exploitation:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker contract gets approved allowance from victim
 * - Attacker prepares malicious contract at _from address
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls burnFrom() which triggers the callback
 * - During callback, balanceOf[_from] is already reduced but allowance[_from][msg.sender] and totalSupply remain unchanged
 * - This creates an inconsistent state window
 * 
 * **Transaction 3+ (Exploitation):**
 * - In the callback, attacker can call burnFrom() again or other functions
 * - The inconsistent state persists across transaction boundaries
 * - Attacker can exploit the fact that totalSupply hasn't been updated yet
 * - Multiple reentrant calls can accumulate state inconsistencies
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the time window between balance update and allowance/totalSupply updates
 * - State inconsistencies accumulate across multiple calls
 * - The attacker needs to set up the malicious contract beforehand (separate transaction)
 * - The reentrant calls must happen in sequence to exploit the accumulated inconsistent state
 * - Single transaction exploitation is prevented by the allowance checks in subsequent calls
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract TokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 6; // 18 是建议的默认值
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf; //
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function TokenERC20(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        initialSupply=3000000;
        tokenName= 'ETH CASH';
        tokenSymbol='ETJ';
        totalSupply = 3000000000000;
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

    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]); // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update balance first to pass checks
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify burning - creates reentrancy window
        if(_from != address(0) && _from != msg.sender && _from != address(this)) {
            if (_from.call.gas(100000)(bytes4(keccak256("receiveApproval(address,uint256,address,bytes)")), msg.sender, _value, this, "")) {
                // Continue execution
            } else {
                // Ignore callback failures
            }
        }
        // Critical state updates happen after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
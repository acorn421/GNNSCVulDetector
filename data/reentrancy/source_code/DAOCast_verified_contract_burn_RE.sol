/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `burnNotificationHandlers`: Maps addresses to their burn notification handler contracts
 *    - `burnInProgress`: Tracks if a burn is currently in progress for an address
 * 
 * 2. **External Call Before State Updates**: Added an external call to a user-controllable contract (`handler.call()`) before updating the critical state variables (`balanceOf` and `totalSupply`).
 * 
 * 3. **Stateful Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker calls a setup function (not shown but would exist) to register a malicious contract as their burn notification handler
 *    - **Transaction 2**: Attacker calls `burn()` with a specific value, triggering the external call to their malicious contract
 *    - **Transaction 3+**: The malicious contract can call other functions (like `transfer()` or `approve()`) while the burn is in progress, exploiting the inconsistent state where the balance check passed but the balance hasn't been updated yet
 * 
 * 4. **Multi-Transaction Dependency**:
 *    - The vulnerability requires the attacker to first register a malicious handler (separate transaction)
 *    - The exploit leverages the persistent state where `burnInProgress[msg.sender] = true` prevents immediate reentrancy to the same `burn()` function
 *    - However, the attacker can still call other functions while the burn is in progress, creating race conditions and state inconsistencies
 *    - The vulnerability becomes more powerful when combined with other functions that don't check the `burnInProgress` flag
 * 
 * 5. **Realistic Implementation**: The burn notification pattern is realistic - many DeFi protocols implement similar callback mechanisms for integration with other contracts or protocols.
 * 
 * The vulnerability is stateful because it depends on the persistent mapping of notification handlers and the burn progress flag. It's multi-transaction because the attacker must first register their malicious handler, then trigger the burn to exploit the external call timing. The incomplete state (balance checked but not yet updated) can be exploited by calling other contract functions during the external call window.
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

    // ===== SMARTINJECT: Begin Reentrancy State =====
    mapping (address => address) public burnNotificationHandlers;
    mapping (address => bool) public burnInProgress;
    // ===== SMARTINJECT: End Reentrancy State =====

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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(!burnInProgress[msg.sender]);
        burnInProgress[msg.sender] = true;
        address handler = burnNotificationHandlers[msg.sender];
        if (handler != address(0)) {
            // Call external contract before updating state
            handler.call(abi.encodeWithSignature("onBurnRequest(address,uint256)", msg.sender, _value));
        }
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        burnInProgress[msg.sender] = false;
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}

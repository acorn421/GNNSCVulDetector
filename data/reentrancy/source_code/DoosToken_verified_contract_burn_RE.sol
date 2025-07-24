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
 *    - `burnInProgress[address]`: Tracks if a burn operation is currently in progress
 *    - `pendingBurnAmount[address]`: Stores the amount being burned during the operation
 * 
 * 2. **External Call Before State Update**: Added a call to `msg.sender.call()` to notify about the burn operation BEFORE updating the balance and totalSupply. This violates the Checks-Effects-Interactions pattern.
 * 
 * 3. **Stateful Tracking**: The function now maintains state across the execution that can be exploited by reentrant calls.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 
 * **Transaction 1**: Initial burn call
 * - User calls `burn(1000)` with balance of 1000 tokens
 * - `burnInProgress[user] = true` and `pendingBurnAmount[user] = 1000`
 * - External call to `onBurnNotification(1000)` is made
 * - During this call, the malicious contract can call `burn()` again
 * 
 * **Transaction 2**: Reentrant call during external call
 * - The malicious contract's `onBurnNotification` function calls `burn(500)` again
 * - The balance check still passes (balance is still 1000, not yet reduced)
 * - `burnInProgress[user]` is already true, but no additional check prevents this
 * - Another external call is made, and state is updated: balance becomes 500, totalSupply reduced by 500
 * 
 * **Transaction 3**: Completion of original call
 * - Original call completes: balance becomes -500 (underflow), totalSupply reduced by another 1000
 * - User has effectively burned 1500 tokens while only having 1000
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires the external call to trigger a reentrant call back into the same function
 * - The state variables (`burnInProgress`, `pendingBurnAmount`) persist between the nested calls
 * - The exploitation depends on the timing between the balance check and the actual balance update
 * - Single transaction exploitation is not possible because the vulnerability depends on the external call creating a reentrant execution context
 * 
 * The vulnerability is realistic because it mimics real-world patterns where contracts notify external parties about operations, and the state tracking variables make it appear like legitimate functionality for preventing double-spending or tracking operations.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract DoosToken {
    string public name = 'DOOS';
    string public symbol = 'DOOS';
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function DoosToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
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
        emit Transfer(_from, _to, _value);

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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public burnInProgress;
    mapping(address => uint256) public pendingBurnAmount;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        
        // Mark burn as in progress before external call
        burnInProgress[msg.sender] = true;
        pendingBurnAmount[msg.sender] = _value;
        
        // External call to notify burn event before state update
        if (extcodesize(msg.sender) > 0) {
            msg.sender.call(abi.encodeWithSignature("onBurnNotification(uint256)", _value));
            // Continue regardless of call result
        }
        
        // State updates after external call - vulnerable to reentrancy
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear the burn progress flag
        burnInProgress[msg.sender] = false;
        pendingBurnAmount[msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }

    // Inline assembly extcodesize for pre-0.5.0 Solidity
    function extcodesize(address _addr) internal view returns (uint size) {
        assembly { size := extcodesize(_addr) }
    }
}

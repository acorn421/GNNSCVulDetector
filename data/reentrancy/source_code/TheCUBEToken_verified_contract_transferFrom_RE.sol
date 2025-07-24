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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Update**: Added an external call to the recipient contract (`_to`) before decrementing the allowance, creating a classic reentrancy window where the allowance state hasn't been updated yet.
 * 
 * 2. **Token Recipient Notification**: The external call simulates a realistic token recipient notification pattern commonly found in modern token contracts, making the vulnerability appear natural and production-ready.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls transferFrom with a malicious contract as `_to`
 *    - **Callback Phase**: The malicious contract's `onTokenReceived` function is called before allowance is decremented
 *    - **Re-entrance**: The malicious contract can re-enter transferFrom multiple times before the original allowance decrement occurs
 *    - **State Accumulation**: Each re-entrance uses the same allowance value since it hasn't been decremented yet
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability depends on the persistent `allowance` state that exists between function calls
 *    - The attacker needs to first establish an allowance (separate transaction via approve())
 *    - The exploitation requires the callback mechanism to trigger multiple internal calls during the same transaction context
 *    - Each re-entrant call sees the same allowance value, enabling drainage of more tokens than authorized
 * 
 * 5. **Realistic Implementation**: The callback mechanism appears as a legitimate feature for token recipient notifications, making the vulnerability subtle and realistic for production environments.
 * 
 * The vulnerability preserves all original functionality while creating a genuine security flaw that requires state persistence and multiple call sequences to exploit effectively.
 */
pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Added missing interface for ITokenReceiver used in transferFrom
interface ITokenReceiver {
    function onTokenReceived(address _from, address _spender, uint256 _value) external;
}
 
contract TheCUBEToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function TheCUBEToken(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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

    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    // Corrected external call for <0.5.0 Solidity (no try/catch, and no .code.length)> 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to recipient before state update
        // This allows for token recipient notification callbacks
        if (isContract(_to)) {
            // Low-level call to recipient contract
            ITokenReceiver(_to).onTokenReceived(_from, msg.sender, _value);
        }
        
        allowance[_from][msg.sender] -= _value;  // State change happens AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper for contract detection in <0.5.0 
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}

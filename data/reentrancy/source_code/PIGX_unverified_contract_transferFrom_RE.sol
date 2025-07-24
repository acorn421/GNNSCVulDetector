/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a conditional check for contract recipients using `_to.code.length > 0`
 * 2. Inserted an external call to `_to.call()` with `onTokenReceived` callback before allowance deduction
 * 3. The external call occurs after the allowance check but before the allowance state update
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker approves themselves a large allowance from victim's account
 * 2. **Transaction 2**: Attacker calls `transferFrom()` to transfer tokens to their malicious contract
 * 3. **During Transaction 2**: The external call triggers the malicious contract's `onTokenReceived` function
 * 4. **Reentrancy Attack**: The malicious contract recursively calls `transferFrom()` again before the original call completes
 * 5. **State Exploitation**: Since allowance hasn't been decremented yet, the attacker can drain more tokens than authorized
 * 
 * **Why Multi-Transaction Dependency:**
 * - Requires initial allowance setup in separate transaction (Transaction 1)
 * - The actual exploitation happens through the callback mechanism during the transfer (Transaction 2)
 * - The vulnerability leverages the persistent allowance state that was established in previous transactions
 * - Cannot be exploited in a single transaction because the allowance must be pre-established
 * - The attack depends on the accumulated state (allowance) from previous transactions to enable unauthorized transfers
 * 
 * **State Persistence Requirement:**
 * - The `allowance` mapping maintains state between transactions
 * - The vulnerability exploits the window between allowance verification and allowance deduction
 * - Multiple recursive calls can occur before the allowance state is properly updated
 * - Each recursive call sees the same (unchanged) allowance value, enabling over-withdrawal
 */
/**
 *Submitted for verification at Etherscan.io on 2019-08-26
*/

pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }
 
contract PIGX {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);
 

    function PIGX(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to recipient before state updates to enable reentrancy
        if (isContract(_to)) {
            // Notify recipient contract about incoming transfer
            (bool notifySuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of notification success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper for contract detection (Solidity <0.5)
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
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
}

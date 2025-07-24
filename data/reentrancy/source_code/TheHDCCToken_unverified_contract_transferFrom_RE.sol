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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient before updating the allowance state. This creates a reentrancy window where:
 * 
 * 1. **State Accumulation Phase** (Transaction 1+): The attacker can call transferFrom multiple times, and during each call, the external notification to the recipient contract allows reentrancy. Since the allowance check happens before the external call, but the allowance decrement happens after, the attacker can re-enter the function while the allowance is still at its original value.
 * 
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions because:
 *    - Transaction 1: Initial transferFrom call triggers external notification, enabling reentrancy
 *    - During reentrancy: The function can be called again with the same allowance value (not yet decremented)
 *    - Transaction 2+: Subsequent calls can exploit the accumulated state inconsistency between allowance checks and actual decrements
 * 
 * 3. **Stateful Nature**: The vulnerability persists across transactions because:
 *    - The allowance mapping state is modified incrementally with each successful transfer
 *    - The attacker needs to accumulate multiple transfers to drain significant funds
 *    - Each transaction builds upon the state changes from previous transactions
 * 
 * 4. **Exploitation Mechanism**: An attacker can create a malicious contract that implements ITokenReceiver and re-enters transferFrom during the onTokenReceived callback, allowing them to transfer more tokens than their allowance should permit by exploiting the timing of state updates.
 * 
 * This is a realistic vulnerability pattern seen in production tokens that implement recipient notification mechanisms without proper reentrancy protection.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Moved the interface to top-level scope
type ITokenReceiver is address; // Placeholder, not valid in 0.4.x - so define as below
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value, address caller) external returns (bool);
}

contract TheHDCCToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);


    function TheHDCCToken(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // There is no .code.length or Address utility in 0.4.x.
        // To minimally preserve logic and compile, simply call onTokenReceived if the target is a contract.
        // No .code.length, so cannot robustly detect contract here; just call as in older tokens.
        if (_to != address(0)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value, msg.sender);
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

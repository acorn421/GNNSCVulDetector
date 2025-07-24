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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability through a callback mechanism. The vulnerability requires:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker calls `registerBurnCallback()` to register a malicious contract
 * 2. **Burn Transaction**: Attacker calls `burn()` which triggers the callback BEFORE state updates
 * 3. **Reentrant Calls**: The malicious callback can call `burn()` again multiple times before the original state updates complete
 * 
 * **Key Vulnerability Elements:**
 * - External call to user-controlled contract (`burnCallbacks[msg.sender]`) occurs before state updates
 * - State modifications (`balanceOf` and `totalSupply` reduction) happen after the external call
 * - The `pendingBurns` mapping provides state persistence between transactions but doesn't prevent reentrancy
 * - Multiple reentrant calls can drain more tokens than the user actually owns
 * 
 * **Why Multi-Transaction Required:**
 * - Transaction 1: Must register callback contract (state setup)
 * - Transaction 2: Execute burn with reentrancy exploitation
 * - The vulnerability exploits the gap between the external call and state updates within the burn transaction
 * - Each reentrant call sees the unchanged balance, allowing multiple burns of the same tokens
 * 
 * **Realistic Context:**
 * - Burn callbacks are common in DeFi for notifying external systems about token burns
 * - The callback registration pattern is realistic for token contracts
 * - The vulnerability is subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract dragoncoin {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => address) public burnCallbacks;
    mapping(address => bool) public pendingBurns;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function dragoncoin(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // Mark burn as pending to prevent double burns
        pendingBurns[msg.sender] = true;
        // External call to user-registered callback BEFORE state update
        if (burnCallbacks[msg.sender] != address(0)) {
            tokenRecipient(burnCallbacks[msg.sender]).receiveApproval(msg.sender, _value, this, "burn");
        }
        // State updates occur after external call - vulnerability window
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // Clear pending burn flag
        pendingBurns[msg.sender] = false;
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function registerBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
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

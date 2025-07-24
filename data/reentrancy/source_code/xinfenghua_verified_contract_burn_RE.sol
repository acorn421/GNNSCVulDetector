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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that occurs before state updates. This creates a CEI (Checks-Effects-Interactions) violation where the external call to `IBurnCallback.onBurnNotification()` happens before the balance and totalSupply state modifications.
 * 
 * **Key Changes Made:**
 * 1. Added an external callback to a user-controlled contract (`burnCallback`) before state updates
 * 2. The callback allows external contracts to re-enter the burn function while the user's balance is still unmodified
 * 3. This violates the CEI pattern by placing the external interaction before the state effects
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: User calls `burn(100)` with 100 tokens
 * 2. **During Transaction 1**: The callback re-enters `burn(100)` before state updates
 * 3. **Result**: Both burns succeed using the same 100 token balance, effectively burning 200 tokens while only having 100
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the `burnCallback` to be set to a malicious contract address (separate transaction)
 * - The exploit depends on accumulated state (user's balance) that persists between function calls
 * - Each reentrancy call leverages the unchanged state from the previous call within the same transaction
 * - The impact compounds across multiple burn operations that can span multiple transactions
 * 
 * **State Persistence Requirements:**
 * - `balanceOf[msg.sender]` must persist between reentrancy calls
 * - `burnCallback` address must be set and persist in contract state
 * - The vulnerability accumulates effect across multiple nested calls within transactions
 * 
 * This creates a realistic burn callback mechanism that could legitimately exist in production code for notifications, but introduces a critical reentrancy vulnerability due to improper ordering of operations.
 */
pragma solidity ^0.4.16;

interface IBurnCallback {
    function onBurnNotification(address _from, uint256 _value) public;
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract xinfenghua {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;

    address public burnCallback;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function xinfenghua(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // INJECTED: External call to burn callback before state updates
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onBurnNotification(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

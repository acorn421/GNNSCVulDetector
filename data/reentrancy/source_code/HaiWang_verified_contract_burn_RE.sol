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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a burn notification system that calls an external contract (`IBurnNotifier`) before updating the critical state variables `balanceOf[msg.sender]` and `totalSupply`.
 * 
 * 2. **Violated Check-Effects-Interactions (CEI) Pattern**: The external call now occurs after the balance check but before the state modifications, creating a classic reentrancy vulnerability window.
 * 
 * 3. **Added Supporting State Variables**: 
 *    - `burnNotificationContract`: Address of the external notification contract
 *    - `burnNotificationEnabled`: Per-user flag to enable/disable notifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker enables burn notifications by setting `burnNotificationEnabled[attacker] = true`
 * - Attacker deploys malicious contract at `burnNotificationContract`
 * 
 * **Transaction 2 (Initial Burn Call):**
 * - Attacker calls `burn(1000)` with legitimate balance of 1000 tokens
 * - Function checks `balanceOf[attacker] >= 1000` ✓ (passes)
 * - Function calls external contract `onBurnNotification(attacker, 1000)`
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - Inside the external call, attacker's malicious contract calls `burn(1000)` again
 * - The balance check still sees original balance (1000) since state hasn't been updated yet
 * - This can be repeated multiple times during the same external call
 * - Each recursive call can burn additional tokens beyond the actual balance
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The vulnerability depends on the persistent state of `balanceOf` and `totalSupply` across multiple function calls
 * 2. **Setup Requirement**: The attack requires prior setup of the notification system (separate transaction)
 * 3. **Accumulated Effect**: Each reentrancy call accumulates more burned tokens than the attacker actually owns
 * 4. **Cross-Call State Dependency**: The exploit depends on the state remaining unchanged between the balance check and state update across multiple nested calls
 * 
 * **Exploitation Result:**
 * - Attacker can burn more tokens than they actually own
 * - Total supply can be reduced below the actual circulating supply
 * - Token economics become corrupted through accumulated state manipulation
 * - The vulnerability persists and can be exploited repeatedly until the notification system is disabled
 */
pragma solidity ^0.4.19;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnNotifier {
    function onBurnNotification(address sender, uint256 value) external;
}

contract HaiWang {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public burnNotificationEnabled;
    address public burnNotificationContract;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function HaiWang(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        if (burnNotificationContract != address(0) && burnNotificationEnabled[msg.sender]) {
            IBurnNotifier(burnNotificationContract).onBurnNotification(msg.sender, _value);
        }
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
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
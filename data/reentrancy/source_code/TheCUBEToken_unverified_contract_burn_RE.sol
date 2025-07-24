/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Persistence**: Introduced `pendingBurns` mapping to track burns across transactions
 * 2. **Two-Stage Burn Process**: Burns now require multiple transactions - initiation and completion
 * 3. **External Call Integration**: Added callback to `burnNotificationContract` that can trigger reentrancy
 * 4. **State Update Timing**: Moved `totalSupply` reduction to occur after external call and in subsequent transactions
 * 5. **Multi-Transaction Dependency**: The vulnerability requires accumulated state from previous burn initiations
 * 
 * **Exploitation Scenario (Multi-Transaction):**
 * - Transaction 1: User calls burn(100) - balance reduced, pending burn set, external call made
 * - During external call: Malicious contract re-enters burn(50) while first burn is pending
 * - Transaction 2: User calls burn(0) or any burn - completes previous pending burn
 * - Result: User can burn more tokens than they own by exploiting the state inconsistency across transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on pendingBurns state persisting between transactions
 * - Each transaction can leave the contract in an inconsistent state (balance reduced but totalSupply not yet updated)
 * - The exploit requires building up pending burns across multiple calls before the totalSupply catches up
 * - Single-transaction exploitation is prevented by the sequential nature of pending burn completion
 * 
 * This creates a realistic vulnerability where the burn mechanism appears secure in isolation but becomes exploitable when state accumulates across multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnNotification { function onBurnInitiated(address _from, uint256 _value) public; }

contract TheCUBEToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => uint256) public pendingBurns;

    address public burnNotificationContract;

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
        // Stage 1: Check if this is a pending burn completion
        if (pendingBurns[msg.sender] > 0) {
            // Complete the pending burn
            uint256 pendingAmount = pendingBurns[msg.sender];
            pendingBurns[msg.sender] = 0;
            totalSupply -= pendingAmount;
            Burn(msg.sender, pendingAmount);
        }
        // Stage 2: Initiate new burn with external notification
        balanceOf[msg.sender] -= _value;
        pendingBurns[msg.sender] = _value;
        // External call to notify burn listeners before finalizing
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onBurnInitiated(msg.sender, _value);
        }
        // Note: totalSupply reduction happens in next transaction or callback
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

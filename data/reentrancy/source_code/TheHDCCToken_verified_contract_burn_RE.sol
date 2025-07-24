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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled `burnNotifier` contract before state updates. This creates a classic reentrancy pattern where:
 * 
 * **Multi-Transaction Exploitation Flow:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract implementing `IBurnNotifier` and sets it as the `burnNotifier` through a setter function (assumed to exist)
 * 2. **Transaction 2 (Exploit)**: Attacker calls `burn()` with their token balance. The function:
 *    - Checks balance requirement (passes)
 *    - Calls external `onTokenBurn()` callback BEFORE updating state
 *    - In the callback, the attacker can call `burn()` again since their balance hasn't been reduced yet
 *    - This allows burning more tokens than they actually own
 * 
 * **State Persistence Requirement:**
 * - The vulnerability requires the `burnNotifier` address to be set in a previous transaction
 * - The attacker's balance state persists between the setup and exploit transactions
 * - The exploit relies on the accumulated state where the notifier is configured and the user has tokens
 * 
 * **Why Multi-Transaction:**
 * - Setting up the malicious notifier contract requires a separate transaction
 * - The actual exploitation happens in subsequent burn calls
 * - The vulnerability cannot be exploited atomically without prior state setup
 * - Each reentrancy call creates a new transaction context while preserving the vulnerable state
 * 
 * This pattern is realistic as many DeFi protocols implement burn notifications for integration with external systems, making this a plausible production vulnerability.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnNotifier {
    function onTokenBurn(address _from, uint256 _value) public;
}

contract TheHDCCToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;
    
    address public burnNotifier;

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

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn callback before state changes
        if (burnNotifier != address(0)) {
            IBurnNotifier(burnNotifier).onTokenBurn(msg.sender, _value);
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

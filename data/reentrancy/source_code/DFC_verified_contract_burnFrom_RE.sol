/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to `IBurnNotifier(_from).onBurnFrom()` before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first obtain allowances from victim accounts in separate transactions
 * 2. **Stateful Dependency**: The vulnerability relies on persistent state (allowance and balance mappings) that accumulates across transactions
 * 3. **Reentrancy Exploitation**: During the external call, the attacker can re-enter `burnFrom()` with the same unchanged allowance, enabling multiple burns beyond the intended limit
 * 
 * **Multi-Transaction Exploit Scenario:**
 * - Transaction 1: Attacker gets approval from victim for 100 tokens
 * - Transaction 2: Attacker calls burnFrom(victim, 100) → external call triggers → attacker re-enters burnFrom(victim, 100) again before allowance is decremented
 * - Result: 200 tokens burned but only 100 allowance consumed
 * 
 * The vulnerability requires multiple transactions because the attacker needs to build up allowances first, then exploit the reentrancy when those allowances are consumed. The external call creates a window where state hasn't been updated yet, allowing the same allowance to be used multiple times within the nested call chain.
 */
pragma solidity ^0.4.19;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Declare IBurnNotifier interface for external call
interface IBurnNotifier {
    function onBurnFrom(address operator, uint256 value) external;
}
 
contract DFC {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);
 
    function DFC(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before state updates enables reentrancy
        if (_from != msg.sender) {
            // Notify the token holder about the burn operation
            IBurnNotifier(_from).onBurnFrom(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}

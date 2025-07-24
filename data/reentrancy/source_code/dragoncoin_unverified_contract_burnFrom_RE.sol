/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder's contract before state updates. This creates a vulnerability where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to set up and exploit:
 *    - Transaction 1: Attacker sets up allowance for a malicious contract
 *    - Transaction 2: Attacker calls burnFrom, triggering the external call that re-enters
 *    - Re-entrant calls: Manipulate allowance/balance state before original burn completes
 *    - Transaction 3: Exploit the inconsistent state created by the reentrancy
 * 
 * 2. **State Persistence**: The vulnerability relies on persistent state between transactions:
 *    - Allowance values set in previous transactions
 *    - Balance states that accumulate across calls
 *    - The external call creates a window where state is inconsistent
 * 
 * 3. **Realistic Business Logic**: The external call for burn notifications is a realistic feature that might be added to notify token holders about burns, making the vulnerability subtle and believable.
 * 
 * 4. **Exploitation Mechanism**: An attacker can:
 *    - Deploy a malicious contract that implements onBurnNotification
 *    - Set allowance for the malicious contract to burn tokens
 *    - When burnFrom is called, the malicious contract receives the callback before state updates
 *    - The malicious contract can re-enter burnFrom or other functions to manipulate state
 *    - This creates opportunities for double-spending, allowance manipulation, or balance inconsistencies
 * 
 * 5. **Multi-Transaction Requirement**: The vulnerability cannot be exploited in a single transaction because:
 *    - Setting up allowances requires separate transactions
 *    - The exploit depends on accumulated state from previous calls
 *    - Multiple re-entrant calls across transactions create the exploitable conditions
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract dragoncoin {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external contract about burn before state updates
        if (_from != msg.sender && isContract(_from)) {
            // External call to token holder's contract for burn notification
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onBurnNotification(address,uint256)", msg.sender, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }

    // Helper to check if 'addr' is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

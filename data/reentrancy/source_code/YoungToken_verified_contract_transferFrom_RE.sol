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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic checks-effects-interactions violation where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker calls transferFrom() with maximum allowance
 *    - During the external call, the attacker's malicious contract can call transferFrom() again
 *    - Transaction 2: The second call sees the same allowance value (not yet decremented)
 *    - This allows draining more tokens than the original allowance permitted
 * 
 * 2. **Stateful Nature**: The vulnerability depends on persistent state between transactions:
 *    - The allowance mapping persists between calls
 *    - The external call happens before the allowance is decremented
 *    - Multiple reentrancy calls can accumulate to drain funds beyond the intended allowance
 * 
 * 3. **Realistic Implementation**: The callback mechanism mimics real-world patterns like ERC-777 or notification systems, making it a realistic vulnerability that could appear in production code.
 * 
 * 4. **Exploitation Sequence**:
 *    - Setup: Attacker gets approved allowance of 100 tokens
 *    - Attack: Calls transferFrom(owner, maliciousContract, 100)
 *    - Reentrancy: During onTokenReceived callback, calls transferFrom again
 *    - Result: Can potentially transfer 200+ tokens with only 100 allowance
 * 
 * The vulnerability is only exploitable through multiple function calls and requires the persistent allowance state to remain unchanged during the external call window.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Added missing interface for IERC20Receiver (not present in Solidity 0.4.x, so we use call)
interface IERC20Receiver {
    function onTokenReceived(address _from, address _caller, uint256 _value) external;
}

contract YoungToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);

    function YoungToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient before updating allowance (vulnerable external call)
        if (_to != address(0)) {
            // Check code size to emulate _to.code.length > 0 in pre-0.5.0
            uint256 len;
            assembly { len := extcodesize(_to) }
            if (len > 0) {
                // Try-catch not available; use raw call to external contract
                // No revert/require on failure (vulnerable pattern)
                // We assume IERC20Receiver is a known interface
                IERC20Receiver(_to).onTokenReceived(_from, msg.sender, _value);
            }
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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
        balanceOf[_from] -= _value;                        
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a balance check with require() statement
 * 2. Introduced external call to recipient if it's a contract (using assembly call)
 * 3. Moved state updates (balance modifications) to occur AFTER the external call
 * 4. Added code length check to identify contract recipients
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with fallback function
 * 2. **Transaction 2**: Attacker calls transfer() to their malicious contract
 * 3. **During Transaction 2**: External call triggers attacker's fallback function
 * 4. **Reentrancy**: Attacker's fallback calls transfer() again before original state updates
 * 5. **State Manipulation**: Multiple transfers can occur using the same balance due to delayed state updates
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - The exploit only triggers when transferring to a contract address, requiring the attacker to have prepared infrastructure
 * - The reentrancy opportunity depends on the external call occurring before balance updates, which creates a window for state manipulation across the call stack
 * - Multiple nested calls within the same transaction create the exploitation opportunity, but the setup requires separate transactions
 * 
 * **Exploitation Scenario:**
 * 1. Attacker deploys malicious contract with fallback function that calls transfer() again
 * 2. Attacker initiates transfer to malicious contract
 * 3. External call triggers malicious contract's fallback
 * 4. Fallback function calls transfer() again before original balance is updated
 * 5. Multiple transfers execute using same initial balance, allowing token drainage
 * 
 * This creates a realistic vulnerability where the external call mechanism (common in modern tokens for hooks) introduces reentrancy by violating the checks-effects-interactions pattern.
 */
pragma solidity ^0.4.18;

contract SafeMath {

    function SafeMath() public {
    }

    function safeAdd(uint256 _x, uint256 _y) internal returns (uint256) {
        uint256 z = _x + _y;
        assert(z >= _x);
        return z;
    }

    function safeSub(uint256 _x, uint256 _y) internal returns (uint256) {
        assert(_x >= _y);
        return _x - _y;
    }

    function safeMul(uint256 _x, uint256 _y) internal returns (uint256) {
        uint256 z = _x * _y;
        assert(_x == 0 || z / _x == _y);
        return z;
    }

}

contract Variant is SafeMath {
    string public constant standard = 'Token 0.1';
    uint8 public constant decimals = 18;

    // you need change the following three values
    string public constant name = 'Variant';
    string public constant symbol = 'VAR';
    uint256 public totalSupply = 10**9 * 10**uint256(decimals);

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function Variant() public {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value)
    public
    returns (bool success)
    {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check for sufficient balance
        require(balanceOf[msg.sender] >= _value);
        
        // Support for transfer hooks - check if recipient implements ITokenReceiver
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // External call before state update - vulnerable to reentrancy
            bool callSuccess;
            assembly {
                callSuccess := call(gas(), _to, 0, 0, 0, 0, 0)
            }
            // Continue regardless of external call result
        }
        
        // State updates happen after external call - VULNERABLE
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value)
    public
    returns (bool success)
    {
        allowance[_from][msg.sender] = safeSub(allowance[_from][msg.sender], _value);
        balanceOf[_from] = safeSub(balanceOf[_from], _value);
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
    public
    returns (bool success)
    {
        // To change the approve amount you first have to reduce the addresses`
        //  allowance to zero by calling `approve(_spender, 0)` if it is not
        //  already 0 to mitigate the race condition described here:
        //  https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    // disable pay QTUM to this contract
    function () public payable {
        revert();
    }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled spender contract BEFORE updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker calls approve() with their malicious contract address as _spender
 * 2. **During callback**: The malicious contract's onApprovalReceived() function is called, which can re-enter approve() 
 * 3. **Transaction 2+**: The malicious contract can manipulate allowance state across multiple calls since the allowance update happens AFTER the external call
 * 
 * The vulnerability is stateful because:
 * - The allowance mapping persists between transactions
 * - The require() check can be bypassed through careful state manipulation across multiple calls
 * - The malicious spender can accumulate allowances beyond intended limits by re-entering during the callback
 * 
 * This creates a realistic attack scenario where a malicious spender contract can:
 * 1. Get initial approval
 * 2. During the approval callback, re-enter to manipulate allowance state
 * 3. Use subsequent transactions to exploit the accumulated unauthorized allowances
 * 
 * The vulnerability is multi-transaction because it requires the attacker to set up the malicious contract first, then trigger the vulnerable approve() call, and finally exploit the accumulated state in follow-up transactions.
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
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value)
    public
    returns (bool success)
    {
        allowance[_from][msg.sender] = safeSub(allowance[_from][msg.sender], _value);
        balanceOf[_from] = safeSub(balanceOf[_from], _value);
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        emit Transfer(_from, _to, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Enhanced security: notify spender of approval before finalizing
        // This allows spenders to validate the approval in their callback
        if (_isContract(_spender)) {
            // Call spender's approval notification callback
            _spender.call(
                abi.encodeWithSignature("onApprovalReceived(address,uint256)", msg.sender, _value)
            );
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Helper to check if address is contract (for Solidity <0.5, limited way)
    function _isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    // disable pay QTUM to this contract
    function () public payable {
        revert();
    }
}

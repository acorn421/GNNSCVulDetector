/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address (_to) before completing the balance update. The vulnerability works through the following mechanism:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 - Setup**: Attacker deploys a malicious contract and approves tokens to be transferred
 * 2. **Transaction 2 - Initial Transfer**: Legitimate user calls transferFrom() to transfer tokens to the malicious contract
 * 3. **During Transaction 2**: The external call to onTokenReceived() triggers reentrancy
 * 4. **Reentrancy Attack**: The malicious contract calls transferFrom() again before the original call completes balance updates
 * 5. **State Inconsistency**: The allowance has been decremented and sender balance reduced, but recipient balance not yet updated
 * 6. **Exploitation**: The reentrant call can manipulate the inconsistent state to drain additional tokens
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - The vulnerability requires pre-existing allowance state from previous approve() transactions
 * - The malicious contract must be deployed and configured in separate transactions
 * - The exploit leverages the accumulated state from multiple approve() calls across different transactions
 * - Each successful reentrancy creates persistent state changes that enable further exploitation in subsequent transactions
 * 
 * **State Persistence Exploitation:**
 * 
 * - The allowance mappings persist between transactions, building up exploitable allowance amounts
 * - Balance inconsistencies created during reentrancy persist and can be exploited in follow-up transactions
 * - The malicious contract can accumulate tokens across multiple reentrant calls, with each call building on the state changes from previous calls
 * 
 * This creates a realistic vulnerability where an attacker needs to:
 * 1. Deploy malicious contract (Transaction 1)
 * 2. Get approved allowances (Transaction 2-N)
 * 3. Trigger the vulnerable transferFrom (Transaction N+1)
 * 4. Exploit reentrancy during the external call to drain tokens through state manipulation
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of incoming transfer - vulnerable to reentrancy
        if (isContract(_to)) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            require(callSuccess, "Token transfer notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
    public
    returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // disable pay QTUM to this contract
    function () public payable {
        revert();
    }

    // Helper function for contract detection in <=0.4.18
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}

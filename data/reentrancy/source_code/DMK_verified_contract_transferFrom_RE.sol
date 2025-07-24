/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * A stateful, multi-transaction reentrancy vulnerability was introduced by adding a recipient notification hook that calls an external contract (`ITokenReceiver(_to).onTokenReceived()`) after the allowance is deducted but before the balance updates occur. This creates a critical window where an attacker can re-enter the function during the external call.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 - Setup**: Attacker deploys a malicious contract that implements `ITokenReceiver` and gets approved allowance from a victim account through `approve()`.
 * 
 * 2. **Transaction 2 - Initial Transfer**: Attacker calls `transferFrom()` targeting their malicious contract. The function:
 *    - Deducts allowance (state change persists)
 *    - Calls `onTokenReceived()` on the malicious contract
 *    - Malicious contract re-enters `transferFrom()` during this call
 *    - Re-entrant call finds allowance still deducted from step 1, but balances not yet updated
 *    - Can potentially drain more tokens before original balance updates complete
 * 
 * 3. **State Persistence**: The allowance deduction from the first call persists and enables the re-entrant call to pass the allowance check, while the balance states remain in an inconsistent intermediate state.
 * 
 * **Why Multi-Transaction is Required:**
 * - The initial allowance must be set up in a separate transaction via `approve()`
 * - The vulnerability exploits the state gap between allowance deduction and balance updates
 * - The attack requires the external contract to be deployed and the allowance relationship established before exploitation
 * - Re-entrance during the external call creates a sequence-dependent vulnerability that cannot occur in a single atomic transaction
 * 
 * This vulnerability is realistic as recipient notification patterns are common in token contracts, and the timing of state updates creates a genuine exploitable window across multiple transaction contexts.
 */
pragma solidity ^0.4.18;

contract SafeMath {

    constructor() public {
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

interface ITokenReceiver {
    function onTokenReceived(address _from, address _spender, uint256 _value) external;
}

contract DMK is SafeMath {
    string public constant standard = 'Token 0.1';
    uint8 public constant decimals = 18;

    // you need change the following three values
    string public constant name = 'DMK';
    string public constant symbol = 'DMK';
    uint256 public totalSupply = 413 * 10**8 * 10**uint256(decimals);

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
        emit Transfer(0x00, msg.sender, totalSupply);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of incoming transfer before updating balances
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            ITokenReceiver(_to).onTokenReceived(_from, msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // disable pay ETH to this contract
    function () public payable {
        revert();
    }
}

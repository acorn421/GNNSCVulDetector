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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first set up allowances through separate approve() transactions, accumulating state across multiple calls.
 * 
 * 2. **State Persistence Exploitation**: The malicious contract can exploit the persistent allowance state by:
 *    - Transaction 1: Call transferFrom() normally to establish the callback pattern
 *    - Transaction 2: Call transferFrom() again, triggering the onTokenReceived callback
 *    - During the callback, the malicious contract can call transferFrom() again before allowance is decremented
 *    - This allows draining more tokens than the original allowance permitted
 * 
 * 3. **Accumulated State Dependency**: The vulnerability becomes more severe as allowances accumulate across multiple transactions, allowing the attacker to drain proportionally more funds.
 * 
 * 4. **Cross-Transaction Reentrancy**: The vulnerability requires the attacker to build up allowances and balances across multiple transactions, then exploit the reentrancy in a coordinated sequence of calls.
 * 
 * The external call occurs before the allowance state is updated, violating the Checks-Effects-Interactions pattern and creating a window for reentrancy attacks that compound across multiple transactions.
 */
pragma solidity ^0.4.19;

library SafeMath
{
    function mul(uint256 a, uint256 b) internal pure
        returns (uint256)
    {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure
        returns (uint256)
    {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure
        returns (uint256)
    {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure
        returns (uint256)
    {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract TokenVCS{
    using SafeMath for uint;
    
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
        require(_to != address(0));
        require(_value > 0);
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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify recipient before state changes
        if (isContract(_to)) {
            require(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value));
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }

    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
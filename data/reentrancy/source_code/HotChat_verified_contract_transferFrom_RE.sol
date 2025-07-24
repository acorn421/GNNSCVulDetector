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
 * Introduced a reentrancy vulnerability by adding an external call to the recipient contract before completing the transfer. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **State Changes Before External Call**: The allowance is decremented before the external call, creating an inconsistent state where allowance is reduced but the actual transfer hasn't completed yet.
 * 
 * 2. **Multi-Transaction Exploitation Pattern**:
 *    - Transaction 1: Attacker sets up initial allowance and deploys malicious contract
 *    - Transaction 2: Victim calls transferFrom to attacker's contract, triggering the external call
 *    - During the external call (still in Transaction 2): Attacker's contract can re-enter transferFrom while allowance is already decremented but transfer incomplete
 *    - Transaction 3+: Attacker can exploit the state inconsistencies created by the reentrancy
 * 
 * 3. **Stateful Nature**: The vulnerability relies on persistent state changes to allowance mapping that accumulate across multiple calls, and the exploit requires setting up initial conditions in separate transactions.
 * 
 * 4. **Realistic Implementation**: The external call appears as a legitimate recipient notification mechanism, making it a subtle vulnerability that could realistically exist in production code.
 * 
 * The vulnerability cannot be exploited in a single atomic transaction because it requires the setup of allowances, deployment of malicious contracts, and coordination of multiple calls to create the exploitable state conditions.
 */
pragma solidity ^0.4.24;

contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

}

contract HotChat is SafeMath {
    address public owner;
    string public name;
    string public symbol;
    uint public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    mapping (address => bool) public frozenAccount;
    event FrozenFunds(address target, bool frozen);

    bool lock = false;

    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint decimalUnits
    ) public {
        owner = msg.sender;
        name = tokenName;
        symbol = tokenSymbol; 
        decimals = decimalUnits;
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier isLock {
        require(!lock);
        _;
    }
    
    function setLock(bool _lock) onlyOwner public{
        lock = _lock;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
 

    function _transfer(address _from, address _to, uint _value) isLock internal {
        require (_to != 0x0);
        require (balanceOf[_from] >= _value);
        require (balanceOf[_to] + _value > balanceOf[_to]);
        require(!frozenAccount[_from]);
        require(!frozenAccount[_to]);
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to recipient before completing transfer
        // This allows for reentrancy attacks that span multiple transactions
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // Call to recipient contract to notify of incoming transfer
            /* solium-disable-next-line security/no-low-level-calls */
            _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[_from] >= _value); 
        require(_value <= allowance[_from][msg.sender]); 
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }

    
    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        emit FrozenFunds(target, freeze);
    }

    function transferBatch(address[] _to, uint256 _value) public returns (bool success) {
        for (uint i=0; i<_to.length; i++) {
            _transfer(msg.sender, _to[i], _value);
        }
        return true;
    }
}

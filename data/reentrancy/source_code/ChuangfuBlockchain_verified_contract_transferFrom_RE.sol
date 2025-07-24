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
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: The code now includes an external call to `ITransferNotification(_to).onTransferPending()` before the allowance is decremented. This creates a reentrancy opportunity where the external contract can call back into transferFrom.
 * 
 * 2. **Introduced Stateful Pending Transfer Tracking**: Added `pendingTransfers[_from][msg.sender]` mapping that persists across transactions. This creates a window where state is inconsistent between transactions.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls transferFrom() with a malicious contract as `_to`
 *    - The external call to `onTransferPending()` triggers before allowance reduction
 *    - The malicious contract can call back into transferFrom() with the same parameters
 *    - **Transaction 2**: The callback sees the original allowance value (not yet decremented) plus any pending transfers
 *    - This allows spending more than the original allowance
 * 
 * 4. **Stateful Vulnerability**: The vulnerability requires:
 *    - Setting up allowances in prior transactions
 *    - The pendingTransfers state persists between calls
 *    - Multiple function calls to exploit the inconsistent state window
 *    - Cannot be exploited in a single transaction due to the cross-transaction state dependencies
 * 
 * 5. **Realistic Integration**: The "transfer notification" pattern is common in DeFi protocols where recipient contracts need to be notified of incoming transfers, making this injection realistic and subtle.
 * 
 * The vulnerability exploits the race condition between the external call and the allowance update, with the pendingTransfers state creating a cross-transaction attack vector.
 */
pragma solidity ^0.4.24;

interface ITransferNotification {
    function onTransferPending(address from, uint256 value) external;
}

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

contract ChuangfuBlockchain is SafeMath {
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
    
    // Added pendingTransfers to support the vulnerability (as referenced but missing in original code)
    mapping(address => mapping(address => uint256)) public pendingTransfers;

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
        require (_to != address(0));
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // If _to is a contract, call its onTransferPending method
        if (isContract(_to)) {
            // External call to potentially malicious contract (reentrancy)
            ITransferNotification(_to).onTransferPending(_from, _value);
        }
        // Check if this is a second call in the same transaction block
        if (pendingTransfers[_from][msg.sender] > 0) {
            require(_value <= allowance[_from][msg.sender] + pendingTransfers[_from][msg.sender]);
        }
        pendingTransfers[_from][msg.sender] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (pendingTransfers[_from][msg.sender] >= _value) {
            pendingTransfers[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // helper function (not available in 0.4.x): to check if _to is a contract
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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

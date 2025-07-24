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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to `ITokenReceiver(_to).onTokenReceived(_from, msg.sender, _value)` before any state modifications occur.
 * 
 * 2. **Violated Check-Effects-Interactions Pattern**: The external call is made after checks but before state effects (balance and allowance updates).
 * 
 * 3. **Added Contract Existence Check**: Added `_to.code.length > 0` to ensure the call is only made to contracts, making it more realistic.
 * 
 * 4. **Implemented Safe External Call**: Used try-catch to handle external call failures gracefully, maintaining function reliability.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract approves malicious recipient contract to spend tokens
 * - Attacker calls `transferFrom(victim, attackerContract, amount)`
 * - During `onTokenReceived` callback, attacker contract calls `approve()` to increase allowance from victim
 * - State changes: allowance increased, but original transfer state updates complete
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transferFrom(victim, attackerContract, amount)` again
 * - Due to increased allowance from Transaction 1, this succeeds
 * - Attacker can repeat this process multiple times
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Attacker continues calling `transferFrom` with artificially inflated allowances
 * - Each transaction builds on state changes from previous transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Persistence**: The vulnerability exploits persistent state changes in the `allowed` mapping across transactions.
 * 
 * 2. **Cross-Transaction Dependencies**: The exploit depends on allowance modifications from previous transactions to enable subsequent unauthorized transfers.
 * 
 * 3. **Time-Based Exploitation**: The attacker needs time between transactions to set up additional approvals or modify contract state.
 * 
 * 4. **Accumulated Effect**: Each transaction increases the attacker's ability to drain funds, with effects accumulating across multiple calls.
 * 
 * **Realistic Integration:**
 * The `onTokenReceived` hook is a common pattern in modern ERC-20 tokens and DeFi protocols, making this vulnerability subtle and realistic. It appears to be a legitimate feature for notifying recipients of incoming transfers, but the timing of the external call creates the reentrancy opportunity.
 * 
 * **Key Vulnerability Characteristics:**
 * - **Stateful**: Exploits persistent changes in allowance mappings
 * - **Multi-Transaction**: Requires sequence of transactions to maximize damage
 * - **Realistic**: Based on actual token notification patterns
 * - **Subtle**: The vulnerability isn't immediately obvious and preserves intended functionality
 */
pragma solidity ^0.4.24;

library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }  
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = a / b;
    return c;
  } 
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }  
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }  
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

interface ITokenReceiver {
    function onTokenReceived(address from, address spender, uint256 value) external;
}

contract SSO {
    mapping(address => uint256) public balances;
    mapping(address => mapping (address => uint256)) public allowed;
    using SafeMath for uint256;
    address public owner;
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    uint256 private constant MAX_UINT256 = 2**256 -1 ;

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    
    bool lock = false;

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        owner = msg.sender;
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
        
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


    function transfer(
        address _to,
        uint256 _value
    ) public returns (bool) {
        require(balances[msg.sender] >= _value);
        require(msg.sender == _to || balances[_to] <= MAX_UINT256 - _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    ) public returns (bool) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value);
        require(_from == _to || balances[_to] <= MAX_UINT256 -_value);
        require(allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call to recipient before state updates
        // This allows for cross-transaction reentrancy exploitation
        if (_to != address(0) && _isContract(_to)) {
            // Call external contract to notify of incoming transfer
            ITokenReceiver(_to).onTokenReceived(_from, msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        balances[_to] += _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function _isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function balanceOf(
        address _owner
    ) public view returns (uint256) {
        return balances[_owner];
    }

    function approve(
        address _spender,
        uint256 _value
    ) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    ) public view returns (uint256) {
        return allowed[_owner][_spender];
    }
}

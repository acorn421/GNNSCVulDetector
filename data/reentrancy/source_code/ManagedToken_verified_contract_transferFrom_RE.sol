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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to the recipient contract `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))`
 * - The external call is placed AFTER balance updates but BEFORE allowance updates
 * - The call attempts to notify the recipient contract about the transfer
 * - Added a check `if (_to.code.length > 0)` to only call contracts, not EOAs
 * 
 * **2. Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction Sequence Attack:**
 * 1. **Setup Phase (Transaction 1):** Attacker deploys a malicious contract that implements `onTokenReceived` callback
 * 2. **Approval Phase (Transaction 2):** Token owner approves attacker's contract for a specific amount (e.g., 1000 tokens)
 * 3. **Exploitation Phase (Transaction 3):** Attacker calls `transferFrom` to transfer tokens to their malicious contract
 * 4. **Reentrancy Chain:** During the `onTokenReceived` callback, the malicious contract calls `transferFrom` again before the allowance is updated
 * 
 * **Stateful Vulnerability Pattern:**
 * - **State Persistence:** The `allowed[_from][msg.sender]` mapping persists between transactions
 * - **Multi-Call Exploitation:** Each reentrant call can drain more tokens than the original allowance
 * - **Accumulated Damage:** Multiple reentrant calls in a single transaction can drain the entire balance
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Dependency:**
 * - The vulnerability relies on the persistent state of the `allowed` mapping set up in previous transactions
 * - The attacker needs prior approval (separate transaction) to have allowance to exploit
 * - The exploitation itself involves multiple nested calls within a single transaction, but the setup requires separate transactions
 * 
 * **Realistic Attack Scenario:**
 * - **Transaction 1:** Attacker deploys malicious contract with `onTokenReceived` function
 * - **Transaction 2:** Victim approves attacker's contract for X tokens
 * - **Transaction 3:** Attacker initiates `transferFrom`, triggering reentrancy during the callback
 * - **During Transaction 3:** Multiple reentrant calls occur before allowance is updated, draining more than approved amount
 * 
 * **4. Technical Exploitation Details:**
 * 
 * **Malicious Contract Example:**
 * ```solidity
 * contract AttackerContract {
 *     ManagedToken public token;
 *     address public victim;
 *     uint256 public attackCount;
 *     
 *     function onTokenReceived(address _from, address _to, uint256 _value) external {
 *         if (attackCount < 3 && token.allowance(victim, address(this)) > 0) {
 *             attackCount++;
 *             token.transferFrom(victim, address(this), _value);
 *         }
 *     }
 * }
 * ```
 * 
 * **Exploitation Flow:**
 * 1. Victim approves attacker contract for 1000 tokens
 * 2. Attacker calls `transferFrom(victim, attackerContract, 1000)`
 * 3. Tokens are transferred to attacker contract
 * 4. `onTokenReceived` callback is triggered
 * 5. Before allowance is updated, attacker calls `transferFrom` again
 * 6. This can repeat multiple times, draining more than the approved amount
 * 
 * **5. Persistence Across Transactions:**
 * - The allowance state set in previous transactions enables the vulnerability
 * - Each successful reentrancy attempt modifies the balance state
 * - The vulnerability compounds across multiple reentrant calls within a single transaction
 * - The setup (approval) and exploitation span multiple separate transactions
 * 
 * This creates a realistic, stateful, multi-transaction reentrancy vulnerability that requires careful sequencing and state management to exploit effectively.
 */
pragma solidity ^0.4.17;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}
  
contract ManagedToken {
    using SafeMath for uint256;


    address public owner = msg.sender;
    address public crowdsaleContractAddress;

    string public name;
    string public symbol;

    bool public locked = true;
        
    uint8 public decimals = 18;

    modifier unlocked() {
        require(!locked);
        _;
    }


    // Ownership

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier onlyCrowdsale() {
        require(msg.sender == crowdsaleContractAddress);
        _;
    }

    modifier ownerOrCrowdsale() {
        require(msg.sender == owner || msg.sender == crowdsaleContractAddress);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner returns (bool success) {
        require(newOwner != address(0));      
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        return true;
    }


    // ERC20 related functions

    uint256 public totalSupply = 0;

    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;


    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function transfer(address _to, uint256 _value) unlocked public returns (bool) {
        require(_to != address(0));
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }


    function transferFrom(address _from, address _to, uint256 _value) unlocked public returns (bool) {
        require(_to != address(0));
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about the transfer before updating allowance
        if (isContract(_to)) {
            // Solidity 0.4.x does not support ABI encoding natively, so we use low-level call as in the pattern
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue execution even if notification fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = _allowance.sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper to check if address is a contract (since "code" member does not exist in 0.4.x)
    function isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    function approve(address _spender, uint256 _value) unlocked public returns (bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function increaseApproval (address _spender, uint _addedValue) unlocked public
        returns (bool success) {
            allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
            emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
            return true;
    }

    function decreaseApproval (address _spender, uint _subtractedValue) unlocked public
        returns (bool success) {
            uint oldValue = allowed[msg.sender][_spender];
            if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
            } else {
            allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
            }
            emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
            return true;
    }



    constructor(string _name, string _symbol, uint8 _decimals) public {
        require(bytes(_name).length > 1);
        require(bytes(_symbol).length > 1);
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }


    function setNameAndTicker(string _name, string _symbol) onlyOwner public returns (bool success) {
        require(bytes(_name).length > 1);
        require(bytes(_symbol).length > 1);
        name = _name;
        symbol = _symbol;
        return true;
    }

    function setLock(bool _newLockState) ownerOrCrowdsale public returns (bool success) {
        require(_newLockState != locked);
        locked = _newLockState;
        return true;
    }

    function setCrowdsale(address _newCrowdsale) onlyOwner public returns (bool success) {
        crowdsaleContractAddress = _newCrowdsale;
        return true;
    }

    function mint(address _for, uint256 _amount) onlyCrowdsale public returns (bool success) {
        balances[_for] = balances[_for].add(_amount);
        totalSupply = totalSupply.add(_amount);
        emit Transfer(0, _for, _amount);
        return true;
    }

    function demint(address _for, uint256 _amount) onlyCrowdsale public returns (bool success) {
        balances[_for] = balances[_for].sub(_amount);
        totalSupply = totalSupply.sub(_amount);
        emit Transfer(_for, 0, _amount);
        return true;
    }

}

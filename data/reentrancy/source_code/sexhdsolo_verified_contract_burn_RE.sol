/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability through a burn reward system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `burnNotificationContract` before state updates
 * 2. Introduced persistent state variables: `cumulativeBurns[msg.sender]` and `totalBurnedAllTime`
 * 3. Added external call to `burnRewardContract` after state updates but before function completion
 * 4. The reward processing depends on accumulated burn amounts (`cumulativeBurns[msg.sender] >= minBurnForReward`)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burn()` with small amount, building up `cumulativeBurns` but not reaching `minBurnForReward`
 * 2. **Transaction 2**: Attacker calls `burn()` again, this time `cumulativeBurns` reaches the threshold
 * 3. **Exploitation**: The external call to `processBurnReward()` allows the attacker's contract to re-enter `burn()` while the current transaction's state changes are committed but the function hasn't completed
 * 4. **State Manipulation**: During reentrancy, the attacker can manipulate the accumulated burn state or call other functions that depend on the modified balances
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on accumulated state (`cumulativeBurns`) that builds up across multiple burn operations
 * - Single transaction exploitation is prevented because the attacker needs to first build up sufficient burn history
 * - The reward threshold mechanism ensures that the vulnerable external call only happens after multiple burns
 * - The persistent state changes between transactions create the conditions necessary for exploitation
 * 
 * **Realistic Context:**
 * This mirrors real-world DeFi patterns where protocols track user activity over time and provide rewards based on accumulated actions, making the vulnerability both subtle and realistic.
 */
pragma solidity ^0.4.16;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface BurnNotificationInterface {
    function onBurnInitiated(address burner, uint256 value) external;
}

interface BurnRewardInterface {
    function processBurnReward(address burner, uint256 cumulativeBurned) external;
}

contract sexhdsolo is owned {

    using SafeMath for uint256;
    
    // Public variables of the token
    string public name = "sexhdsolo";
    string public symbol = "SEX";
    uint8 public decimals = 0;
    uint256 public totalSupply = 10000000;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Burn tracking variables (added)
    mapping(address => uint256) public cumulativeBurns;
    uint256 public totalBurnedAllTime;
    address public burnNotificationContract;
    address public burnRewardContract;
    uint256 public minBurnForReward;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    constructor() public{
        balanceOf[msg.sender] = totalSupply;
    }

    function mintToken(address target, uint256 mintedAmount) public onlyOwner {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, owner, mintedAmount);
        Transfer(owner, target, mintedAmount);
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
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
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add external call to burn notification system before state updates
        if(burnNotificationContract != address(0)) {
            BurnNotificationInterface(burnNotificationContract).onBurnInitiated(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update cumulative burn tracking for potential rewards
        cumulativeBurns[msg.sender] += _value;
        totalBurnedAllTime += _value;
        // External call to process burn rewards - vulnerable to reentrancy
        if(burnRewardContract != address(0) && cumulativeBurns[msg.sender] >= minBurnForReward) {
            BurnRewardInterface(burnRewardContract).processBurnReward(msg.sender, cumulativeBurns[msg.sender]);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function distributeToken(address[] addresses, uint256 _value) public onlyOwner {
        for (uint i = 0; i < addresses.length; i++) {
            balanceOf[owner] -= _value;
            balanceOf[addresses[i]] += _value;
            Transfer(owner, addresses[i], _value);
        }
    }
}
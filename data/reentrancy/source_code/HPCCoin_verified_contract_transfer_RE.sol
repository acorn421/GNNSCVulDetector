/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism that calls the recipient contract's `onTokenReceived` function before updating the balances mapping
 * 2. **Added Contract Detection**: Implemented `isContract()` helper function to identify contract addresses
 * 3. **Positioned Call Before State Changes**: The external call occurs after validation but before balance updates, creating a critical reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * This vulnerability requires multiple transactions to be effectively exploited:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `onTokenReceived()`
 * - The malicious contract is designed to re-enter the transfer function when called
 * 
 * **Transaction 2 (Initial Transfer):**
 * - Victim calls `transfer()` to send tokens to the attacker's contract
 * - The function passes validation checks (sufficient balance, valid recipient)
 * - External call triggers `onTokenReceived()` on attacker's contract
 * - At this point, balances are NOT yet updated, so victim's balance still shows original amount
 * 
 * **Transaction 3 (Reentrancy Attack):**
 * - Within the `onTokenReceived()` callback, attacker's contract calls `transfer()` again
 * - Since balances haven't been updated from the first call, the balance check passes again
 * - This creates a second transfer using the same funds
 * - The attacker can repeat this pattern multiple times within the callback
 * 
 * **Transaction 4+ (Draining):**
 * - Attacker can continue exploiting the inconsistent state across multiple calls
 * - Each re-entrant call can transfer additional tokens before the original state updates occur
 * - The accumulated effect allows draining more tokens than the victim actually owns
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on the persistent imbalance between actual balances and the accounting state across multiple function calls
 * 2. **Sequence Dependency**: The exploit requires a specific sequence: initial transfer → callback → re-entrant transfers → state updates
 * 3. **Cross-Call State Manipulation**: The effectiveness increases with multiple re-entrant calls, each building on the previous inconsistent state
 * 4. **Persistent Storage Impact**: Each re-entrant call affects the persistent `balances` mapping, creating compound effects that accumulate across transactions
 * 
 * The vulnerability is realistic because token notification callbacks are a common pattern in modern token contracts, but the placement before state updates violates the Checks-Effects-Interactions pattern, creating a classic reentrancy vulnerability that requires multiple function calls to fully exploit.
 */
pragma solidity ^0.4.24;

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

contract HPCCoin {

    using SafeMath for uint256;

    address public owner = msg.sender;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    string public constant name = "Happiness Chain";
    string public constant symbol = "HPC";
    uint public constant decimals = 8;
    uint256 public totalSupply = 1000000000e8;

    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Burn(address indexed burner, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner,"only owner allow");
        _;
    }

    // mitigates the ERC20 short address attack
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length >= size + 4);
        _;
    }

    constructor() public {
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }

    function balanceOf(address _owner) public view returns (uint256) {
	    return balances[_owner];
    }

    function transfer(address _to, uint256 _amount) public onlyPayloadSize(2 * 32) returns (bool success) {

        require(_to != address(0),"to address error");
        require(_amount <= balances[msg.sender],"from token not enough");
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient before updating balances - creates reentrancy window
        if (isContract(_to)) {
            // Call recipient contract to notify about incoming transfer
            require(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount));
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        balances[msg.sender] = balances[msg.sender].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(msg.sender, _to, _amount);
        return true;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    function isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function transferFrom(address _from, address _to, uint256 _amount) public onlyPayloadSize(3 * 32) returns (bool success) {

        require(_to != address(0),"to address error");
        require(_amount <= balances[_from],"from token not enough");
        require(_amount <= allowed[_from][msg.sender],"insufficient credit");

        balances[_from] = balances[_from].sub(_amount);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(_from, _to, _amount);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
    }
}
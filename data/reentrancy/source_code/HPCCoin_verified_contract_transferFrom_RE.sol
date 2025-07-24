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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient contract before updating balances and allowances. The vulnerability creates a checks-effects-interactions pattern violation where:
 * 
 * 1. **Stateful Multi-Transaction Exploitation**: An attacker can deploy a malicious contract that accumulates unauthorized allowances across multiple transactions. The attack requires:
 *    - Transaction 1: Attacker gets legitimate allowance from victim
 *    - Transaction 2: Victim calls transferFrom with malicious contract as recipient
 *    - The malicious contract's onTokenReceived callback calls transferFrom again before original state updates
 *    - This allows draining tokens beyond the original allowance through recursive calls
 * 
 * 2. **State Persistence Requirements**: The vulnerability exploits the persistent state of `balances` and `allowed` mappings that remain unchanged during the external call, enabling the attacker to:
 *    - Accumulate multiple transfers before any balance updates occur
 *    - Bypass allowance checks by reusing the same allowance multiple times
 *    - Drain victim's tokens through accumulated state manipulation
 * 
 * 3. **Multi-Transaction Dependency**: The attack cannot be executed in a single transaction because:
 *    - Requires pre-existing allowance (separate transaction)
 *    - Needs victim to initiate transferFrom to malicious contract
 *    - Exploits the time gap between external call and state updates
 *    - Depends on accumulated recursive calls across the callback chain
 * 
 * The vulnerability is realistic as recipient notification hooks are common in modern token contracts, making this a subtle but dangerous pattern that preserves the function's intended behavior while introducing the security flaw.
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

        balances[msg.sender] = balances[msg.sender].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(msg.sender, _to, _amount);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _amount) public onlyPayloadSize(3 * 32) returns (bool success) {

        require(_to != address(0),"to address error");
        require(_amount <= balances[_from],"from token not enough");
        require(_amount <= allowed[_from][msg.sender],"insufficient credit");
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient before state updates - creates reentrancy vulnerability
        if(_isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _amount));
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        balances[_from] = balances[_from].sub(_amount);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(_from, _to, _amount);
        return true;
    }

    // Helper function to check if an address is a contract (compatible with Solidity 0.4.x)
    function _isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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

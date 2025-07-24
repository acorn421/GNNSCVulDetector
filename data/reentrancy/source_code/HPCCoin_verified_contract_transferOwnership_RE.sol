/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variable**: `pendingOwnershipTransfers` mapping to track pending ownership transfers between transactions
 * 
 * 2. **External Call Before State Update**: Added `newOwner.call()` to notify the new owner before updating the `owner` state variable, violating the Checks-Effects-Interactions pattern
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Legitimate owner calls `transferOwnership(maliciousContract)`
 *    - The external call to `maliciousContract.onOwnershipTransferred()` executes
 *    - **Transaction 2**: Malicious contract re-enters `transferOwnership()` during the callback
 *    - Since `owner` hasn't been updated yet, the `onlyOwner` check still passes
 *    - The malicious contract can set itself as owner or manipulate the pending state
 * 
 * 4. **State Persistence**: The `pendingOwnershipTransfers` mapping persists between transactions, allowing the vulnerability to be exploited across multiple calls
 * 
 * 5. **Multi-Transaction Requirement**: The vulnerability requires:
 *    - Initial transaction to trigger the external call
 *    - Reentrancy call during the callback (separate execution context)
 *    - State manipulation across these multiple transaction boundaries
 * 
 * This creates a realistic vulnerability where an attacker can exploit the delayed state update and persistent pending state to gain unauthorized ownership control through a sequence of transactions.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingOwnershipTransfers;
    
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner != address(0)) {
            // Mark as pending transfer to enable multi-transaction exploitation
            pendingOwnershipTransfers[newOwner] = true;
            
            // External call to notify new owner - enables reentrancy
            if (newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner)) {
                // State change happens after external call - vulnerable to reentrancy
                owner = newOwner;
                pendingOwnershipTransfers[newOwner] = false;
            }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
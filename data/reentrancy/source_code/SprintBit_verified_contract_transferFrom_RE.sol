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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability is triggered through a sequence of operations:
 * 
 * **Transaction 1 (Setup)**: Attacker approves tokens to a malicious contract and sets up the attack scenario.
 * 
 * **Transaction 2 (Exploit)**: When transferFrom is called with a malicious recipient contract:
 * 1. Recipient balance is updated first (balances[_to] += _value)
 * 2. External call to recipient's onTokenReceived function occurs
 * 3. Malicious recipient can re-enter transferFrom during callback
 * 4. Since sender's balance and allowance aren't updated yet, the re-entrant call passes all checks
 * 5. This allows draining more tokens than the original allowance permitted
 * 
 * **Multi-Transaction Nature**: The vulnerability requires multiple transactions because:
 * - Initial setup (approval) must happen in a previous transaction
 * - The exploit depends on the specific state where recipient balance is updated but sender balance/allowance are not
 * - Multiple re-entrant calls can accumulate to drain more tokens than should be possible
 * - Each re-entrant call depends on the persistent state changes from previous calls
 * 
 * **Realistic Pattern**: This follows the common ERC777/ERC1363 token callback pattern, making it a realistic production vulnerability that developers might introduce when adding recipient notification features.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-10-21
*/

pragma solidity ^0.4.6;

contract SprintBit {

  string public name = "SprintBit";
  string public symbol = "SBT";
  uint public decimals = 18;
  uint public INITIAL_SUPPLY = 100000000000000000000000000;

  mapping(address => uint) balances;
  mapping (address => mapping (address => uint)) allowed;
  uint256 public _totalSupply;
  address public _creator;
  bool bIsFreezeAll = false;
  
  event Transfer(address indexed from, address indexed to, uint value);
  event Approval(address indexed owner, address indexed spender, uint value);
  
  function safeSub(uint a, uint b) internal returns (uint) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint a, uint b) internal returns (uint) {
    uint c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  
  function totalSupply() public constant returns (uint256 total) {
	total = _totalSupply;
  }

  function transfer(address _to, uint _value) public returns (bool success) {
    require(bIsFreezeAll == false);
    balances[msg.sender] = safeSub(balances[msg.sender], _value);
    balances[_to] = safeAdd(balances[_to], _value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
    require(bIsFreezeAll == false);
    uint _allowance = allowed[_from][msg.sender];
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Add balance to recipient first
    balances[_to] = safeAdd(balances[_to], _value);
    
    // Notify recipient contract about incoming transfer (VULNERABLE: external call before state finalization)
    if (isContract(_to)) {
        _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
        // Continue execution regardless of callback result
    }
    
    // Complete the transfer (VULNERABLE: state updates after external call)
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[_from] = safeSub(balances[_from], _value);
    allowed[_from][msg.sender] = safeSub(_allowance, _value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    emit Transfer(_from, _to, _value);
    return true;
  }

  function isContract(address _addr) internal returns (bool) {
    uint length;
    assembly { length := extcodesize(_addr) }
    return length > 0;
  }

  function balanceOf(address _owner) public constant returns (uint balance) {
    return balances[_owner];
  }

  function approve(address _spender, uint _value) public returns (bool success) {
	require(bIsFreezeAll == false);
    allowed[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public constant returns (uint remaining) {
    return allowed[_owner][_spender];
  }

  function freezeAll() public 
  {
	require(msg.sender == _creator);
	bIsFreezeAll = !bIsFreezeAll;
  }
  
  function SprintBit() public {
        _totalSupply = INITIAL_SUPPLY;
	_creator = 0xc66c4A406ff17E976C06025a750ED3723EDA174c;
	balances[_creator] = INITIAL_SUPPLY;
	bIsFreezeAll = false;
  }
  
  function destroy() public  {
	require(msg.sender == _creator);
	selfdestruct(_creator);
  }

}

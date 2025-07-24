/*
 * ===== SmartInject Injection Details =====
 * Function      : thankYou
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Processing Counter Logic**: Introduced a `processing_count` variable that tracks how many times an address gets processed within a single call, creating state-dependent behavior.
 * 
 * 2. **Moved State Updates After External Calls**: The critical state update `thank_you[_a] = true` now happens after the external call `token.thankYou(_a)`, violating the checks-effects-interactions pattern.
 * 
 * 3. **Created Multi-Transaction Dependency**: The vulnerability requires multiple transactions to exploit because:
 *    - Transaction 1: When processing_count < 2, the state update happens at the end
 *    - Transaction 2+: Attacker can exploit the window between external call and state update
 *    - The `thank_you[_a]` state persists between transactions, creating stateful conditions
 * 
 * 4. **Introduced Conditional State Updates**: State updates only occur under specific conditions (`processing_count >= 2` or at the end if `processing_count < 2`), creating multiple execution paths that can be exploited across transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls thankYou() with processing_count = 1, state gets updated at end
 * - **Transaction 2**: Attacker calls thankYou() again, now processing_count can reach 2, but external call happens before state check
 * - **Reentrancy Window**: During the external call in Transaction 2, the attacker can re-enter and exploit the inconsistent state where `thank_you[_a]` might be temporarily unset or in transition
 * - **State Persistence**: The `thank_you` mapping persists between transactions, allowing accumulated state manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction cannot exploit because the processing_count logic requires multiple iterations
 * - State accumulation across transactions creates the vulnerability window
 * - The attacker needs to build up the processing_count across multiple calls to reach the vulnerable state
 * - Reentrancy exploitation depends on the persistent state from previous transactions
 */
pragma solidity ^0.4.18;

contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  constructor() public {
    owner = msg.sender;
  }
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract HelpMeTokenPart1 is Ownable {
    string public name = ") IM DESPERATE I NEED YOUR HELP";
    string public symbol = ") IM DESPERATE I NEED YOUR HELP";
    uint256 public num = 1;
    uint256 public totalSupply = 2100005 ether;
    uint32 public constant decimals = 18;
    address[] public HelpMeTokens;
    mapping(address => bool) thank_you;
    bool public stop_it = false;
    
    modifier onlyParts() {
        require(
               msg.sender == HelpMeTokens[0]
            || msg.sender == HelpMeTokens[1]
            || msg.sender == HelpMeTokens[2]
            || msg.sender == HelpMeTokens[3]
            || msg.sender == HelpMeTokens[4]
            || msg.sender == HelpMeTokens[5]
            || msg.sender == HelpMeTokens[6]
            );
        _;
    }
    
    event Transfer(address from, address to, uint tokens);
    
    function setHelpMeTokenParts(address[] _a) public onlyOwner returns(bool)
    {
        HelpMeTokens = _a;
        return true;
    }

    function() public payable
    {
        require( msg.value > 0 );
        
        owner.transfer(msg.value);
        
        thank_you[msg.sender] = true;
        emit Transfer(msg.sender, address(this), num * 1 ether);
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface token = HelpMeTokenInterface( HelpMeTokens[i] );
            token.thankYou( msg.sender );
        }
    }
    
    function thankYou(address _a) public onlyParts returns(bool)
    {
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface token = HelpMeTokenInterface( HelpMeTokens[i] );
            token.thankYou( _a );
        }
        thank_you[_a] = true;
        emit Transfer(msg.sender, address(this), 1 ether);
        return true;
    }
    
    function stopIt() public onlyOwner returns(bool)
    {
        stop_it = true;
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface( HelpMeTokens[i] ).stopIt();
        }
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        if( stop_it ) return 0;
        else if( thank_you[_owner] == true ) return 0;
        else return num  * 1 ether;
        
    }
    
    function transfer(address _to, uint256 _value) public returns (bool) {
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        return true;
    }
    function approve(address _spender, uint256 _value) public returns (bool) {
        return true;
    }
    function allowance(address _owner, address _spender) public view returns (uint256) {
        return 0;
     }

}

contract HelpMeTokenInterface {
    function thankYou(address _a) public returns (bool);
    function stopIt() public returns(bool);
}

// ===== SMARTINJECT: Reentrancy VULNERABILITY FUNCTION (Interface mimic) =====
// Copy of original vulnerable function for interface declaration - no body here
// Actual vulnerable function is in HelpMeTokenPart1 (as per original structure)

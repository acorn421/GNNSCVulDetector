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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Early State Check**: Added a check `if (thank_you[_a] == true)` at the beginning that returns early but still allows "updates" - this creates a false sense of protection while maintaining the vulnerability window.
 * 
 * 2. **Preserved External Calls Before State Updates**: Maintained the external calls to `token.thankYou(_a)` BEFORE updating the `thank_you[_a] = true` state, creating a classic reentrancy vulnerability window.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: An authorized contract calls `thankYou(victim)` for the first time
 *    - **During Transaction 1**: A malicious contract in the `HelpMeTokens` array receives the `thankYou` call and can re-enter the main contract
 *    - **Reentrancy Window**: The malicious contract can call `thankYou(victim)` again before `thank_you[victim] = true` is set
 *    - **State Accumulation**: Multiple re-entries can occur, each potentially triggering the Transfer event multiple times
 *    - **Transaction 2+**: Subsequent calls from different authorized contracts can exploit the accumulated state inconsistencies
 * 
 * 4. **Why Multi-Transaction**: The vulnerability requires:
 *    - Initial call from an authorized contract (onlyParts modifier)
 *    - Malicious contract must be in the HelpMeTokens array (set in previous transactions)
 *    - State build-up over multiple transactions where `thank_you` mapping is manipulated
 *    - Cross-contract interactions that span multiple transactions to fully exploit
 * 
 * 5. **Realistic Vulnerability**: This follows real-world patterns where:
 *    - Developers add "protective" checks that don't actually prevent reentrancy
 *    - External calls to arrays of contracts are common in token ecosystems
 *    - State updates after external calls create natural reentrancy windows
 *    - The vulnerability appears subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.18;


contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  function Ownable() public {
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


contract HelpMeTokenInterface{
    function thankYou( address _a ) public returns(bool);
    function stopIt() public returns(bool);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Multi-transaction vulnerability: state check without immediate update
        if (thank_you[_a] == true) {
            return true; // Already thanked, but allow re-entry for "updates"
        }
        
        // External calls before state updates - classic reentrancy pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface token = HelpMeTokenInterface( HelpMeTokens[i] );
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerable: external call can re-enter before state is updated
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            token.thankYou( _a );
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // State update happens after external calls - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
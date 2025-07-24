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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to both the previous owner and new owner BEFORE updating the owner state. This creates a multi-transaction exploitation scenario where:
 * 
 * **Changes Made:**
 * 1. Added external call to `previousOwner.call(abi.encodeWithSignature("onOwnershipTransfer(address)", newOwner))` before state update
 * 2. Added external call to `newOwner.call(abi.encodeWithSignature("acceptOwnership()"))` before state update
 * 3. Both calls occur before the critical `owner = newOwner` state change, violating checks-effects-interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract `MaliciousOwner` 
 * - Current owner calls `transferOwnership(MaliciousOwner)`
 * - External call to `MaliciousOwner.acceptOwnership()` triggers reentrancy
 * - In the reentrant call, `MaliciousOwner` can call other `onlyOwner` functions because `owner` hasn't been updated yet
 * - The malicious contract can set up state for future exploitation (e.g., modify `HelpMeTokens` array, change critical contract parameters)
 * 
 * **Transaction 2 (Exploitation):**
 * - After the initial transaction completes, ownership has transferred to `MaliciousOwner`
 * - The attacker can now exploit the previously set state from Transaction 1
 * - Combined with the new ownership, this creates a compound vulnerability
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The intermediate state during reentrancy in Transaction 1 allows setting up conditions
 * 2. **Ownership Transition**: The vulnerability exploits the gap between external calls and state updates
 * 3. **Accumulated Impact**: The damage from Transaction 1 (state manipulation) combines with Transaction 2 (ownership abuse)
 * 4. **Time Window**: The vulnerability creates a time window where the contract is in an inconsistent state across transactions
 * 
 * This vulnerability is realistic because many contracts implement ownership notification systems and the external calls appear legitimate for notifying parties about ownership changes.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Store the previous owner for notification
    address previousOwner = owner;
    
    // Notify the previous owner about ownership transfer BEFORE state change
    if (previousOwner != address(0) && previousOwner != newOwner) {
        bool success1 = previousOwner.call(abi.encodeWithSignature("onOwnershipTransfer(address)", newOwner));
        // Continue regardless of success to maintain functionality
    }
    
    // Notify the new owner to accept ownership BEFORE state change
    if (newOwner != address(0)) {
        bool success2 = newOwner.call(abi.encodeWithSignature("acceptOwnership()"));
        // Continue regardless of success to maintain functionality
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

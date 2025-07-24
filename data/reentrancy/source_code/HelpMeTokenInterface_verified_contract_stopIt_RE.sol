/*
 * ===== SmartInject Injection Details =====
 * Function      : stopIt
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Modified the stopIt() function to introduce a stateful, multi-transaction reentrancy vulnerability by reversing the order of operations. The function now makes external calls to all HelpMeTokens contracts BEFORE updating the critical stop_it state variable, creating a reentrancy window.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1: Setup Phase**
 * - Attacker deploys a malicious contract implementing HelpMeTokenInterface
 * - Through social engineering, bribes, or compromised owner account, the malicious contract gets added to the HelpMeTokens array via setHelpMeTokenParts()
 * 
 * **Transaction 2: Exploit Execution**
 * - Owner calls stopIt() on the main contract
 * - The function enters the loop and calls stopIt() on each contract in HelpMeTokens array
 * - When it reaches the attacker's malicious contract, the malicious stopIt() function:
 *   - Re-enters the main contract's functions while stop_it is still false
 *   - Can call balanceOf(), transfer(), or other functions that depend on stop_it state
 *   - Can manipulate thank_you mappings or trigger additional state changes
 *   - Can drain funds or manipulate token balances before the stop mechanism activates
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **Setup Dependency**: The attacker must first get their malicious contract into the HelpMeTokens array through a separate transaction
 * 2. **State Persistence**: The vulnerability depends on the persistent state of the HelpMeTokens array between transactions
 * 3. **Timing Window**: The exploit only works during the specific window between external calls and state updates
 * 4. **Authorization Requirements**: Getting the malicious contract added requires owner privileges in a prior transaction
 * 
 * **Critical Vulnerability Details:**
 * - The stop_it variable controls critical contract behavior (balanceOf returns 0 when stop_it is true)
 * - During reentrancy, stop_it is still false, allowing normal operations
 * - Malicious contracts can exploit this window to perform unauthorized actions
 * - The vulnerability persists until the stopIt() function completes and sets stop_it = true
 * 
 * This creates a realistic, stateful reentrancy that requires careful orchestration across multiple transactions and leverages the contract's existing architecture.
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

contract HelpMeTokenInterface{
    function thankYou( address _a ) public returns(bool);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    address[] public HelpMeTokens;
    bool public stop_it = false;
    modifier onlyOwner() { _; } // placeholder to allow compilation
    function stopIt() public onlyOwner returns(bool)
    {
        // First make external calls to all token parts
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface( HelpMeTokens[i] ).stopIt();
        }
        
        // Then update state - this creates a reentrancy window
        stop_it = true;
        
        return true;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

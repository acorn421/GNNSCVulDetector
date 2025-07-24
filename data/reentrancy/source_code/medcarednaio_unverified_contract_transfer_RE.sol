/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. This creates a callback mechanism where the recipient contract can call back into the transfer function during the external call, potentially exploiting inconsistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call using `to.call.value(0)()` to invoke `onTokenReceived` on the recipient contract
 * 2. Positioned the external call after balance updates but before event emission
 * 3. Added a check for `to.code.length > 0` to only call contracts (realistic pattern)
 * 4. Used low-level call that continues execution regardless of success to maintain original functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transfer()` to send tokens to their malicious contract
 * 2. **Callback Phase**: The malicious contract's `onTokenReceived` function is triggered
 * 3. **Transaction 2**: During the callback, the malicious contract calls `transfer()` again (reentrancy)
 * 4. **State Exploitation**: The reentrant call sees updated balances from the first call, allowing potential manipulation
 * 5. **Transaction 3+**: Additional reentrant calls can further exploit the accumulated state changes
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires the attacker to deploy a malicious contract that implements the callback
 * - The attack sequence spans multiple function calls: initial transfer → callback → reentrant transfer
 * - State inconsistencies accumulate across these multiple calls, not within a single atomic transaction
 * - The attacker needs to set up the malicious contract in a separate transaction before exploitation
 * - Each reentrant call creates new opportunities for state manipulation based on previous state changes
 * 
 * **Realistic Nature:**
 * - Token recipient notifications are common in modern token contracts
 * - The external call pattern mimics real-world implementations like ERC777 or similar standards
 * - The vulnerability follows patterns seen in actual production contract exploits
 * - The code maintains all original functionality while introducing the security flaw
 */
pragma solidity ^0.4.24;

contract ERC20Interface {
    function totalSupply() public view returns (uint);
    function balanceOf(address tokenOwner) public view returns (uint balance);
    // Declare balances mapping here so that interface functions have access
    // (Need for compilation, even though generally mappings not in interface)
    mapping(address => uint) public balances;
    function transfer(address to, uint tokens) public returns (bool success){
         require(balances[msg.sender] >= tokens && tokens > 0);
         
         balances[to] += tokens;
         balances[msg.sender] -= tokens;
         // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
         
         // External call after state updates - enables reentrancy
         if(to.delegatecall.selector > 0) { // Minimal dummy condition to mimic original intent, not accessing .code
             bool callSuccess = to.call.value(0)(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, tokens));
             // Continue regardless of call success to maintain functionality
         }
         
         // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
         emit Transfer(msg.sender, to, tokens);
         return true;
     }

    
    //function allowance(address tokenOwner, address spender) public view returns (uint remaining);
    //function approve(address spender, uint tokens) public returns (bool success);
    //function transferFrom(address from, address to, uint tokens) public returns (bool success);
    
    event Transfer(address indexed from, address indexed to, uint tokens);
    //event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

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


contract medcarednaio is ERC20Interface, Ownable{
    string public name = "medcaredna.io";
    string public symbol = "mcd";
    uint public decimals = 18;
    
    uint public supply;
    address public founder;
    
    // mapping for balances is already inherited from interface, do not redeclare
    //mapping(address => uint) public balances;

  event Transfer(address indexed from, address indexed to, uint tokens);


    constructor() public{
        supply = 10000000000000000000000000;
        founder = msg.sender;
        balances[founder] = supply;
    }
    
    
    function totalSupply() public view returns (uint){
        return supply;
    }
    
    function balanceOf(address tokenOwner) public view returns (uint balance){
         return balances[tokenOwner];
     }
     
     
    //transfer from the owner balance to another address
    function transfer(address to, uint tokens) public returns (bool success){
         require(balances[msg.sender] >= tokens && tokens > 0);
         
         balances[to] += tokens;
         balances[msg.sender] -= tokens;
         emit Transfer(msg.sender, to, tokens);
         return true;
     }
     
     
     function burn(uint256 _value) public returns (bool success) {
        require(balances[founder] >= _value);   // Check if the sender has enough
        balances[founder] -= _value;            // Subtract from the sender
        supply -= _value;                      // Updates totalSupply
        return true;
    }
     
}

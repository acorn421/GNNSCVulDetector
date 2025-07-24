/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to msg.sender before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker calls burn() with a contract address as msg.sender that implements onBurnNotification()
 * 2. **During Transaction 1**: The external call triggers the attacker's onBurnNotification() function, which can re-enter burn() before the original state updates (balances[founder] -= _value and supply -= _value) are executed
 * 3. **Transaction 2+**: The attacker can repeatedly exploit the inconsistent state where the require check passes but state hasn't been updated yet
 * 
 * **Multi-Transaction Nature:**
 * - The vulnerability relies on accumulated state corruption across multiple burn operations
 * - Each reentrancy call can pass the require(balances[founder] >= _value) check using the same founder balance
 * - State becomes increasingly inconsistent as supply decreases multiple times while balances[founder] only decreases once per original call
 * - The exploit builds up over multiple transactions, creating a larger discrepancy between actual token supply and recorded balances
 * 
 * **Realistic Integration:**
 * - The external call appears as a legitimate notification mechanism for burn events
 * - Common pattern in DeFi protocols to notify external contracts about token operations
 * - The founder check makes the vulnerability less obvious while still being exploitable by non-founder addresses
 */
pragma solidity ^0.4.24;

contract ERC20Interface {
    function totalSupply() public view returns (uint);
    function balanceOf(address tokenOwner) public view returns (uint balance);
    function transfer(address to, uint tokens) public returns (bool success);

    
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
    
    mapping(address => uint) public balances;


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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call before state updates - vulnerable to reentrancy
        if (msg.sender != founder) {
            // Notify external contract about burn operation
            (bool callSuccess,) = msg.sender.call(abi.encodeWithSignature("onBurnNotification(uint256)", _value));
            require(callSuccess, "External notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[founder] -= _value;            // Subtract from the sender
        supply -= _value;                      // Updates totalSupply
        return true;
    }
     
}
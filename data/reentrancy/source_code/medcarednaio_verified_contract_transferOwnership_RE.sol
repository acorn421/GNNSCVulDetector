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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner before updating the owner state. This creates a classic Check-Effects-Interactions (CEI) pattern violation where:
 * 
 * 1. **State Setup Phase (Transaction 1)**: The attacker deploys a malicious contract that implements the `onOwnershipTransferred` callback
 * 2. **Exploitation Phase (Transaction 2)**: When `transferOwnership` is called with the malicious contract address, the external call to `onOwnershipTransferred` occurs while the original owner is still set
 * 3. **Reentrancy Attack**: During the callback, the malicious contract can re-enter `transferOwnership` or other owner-only functions while still appearing as the legitimate owner in the modifier check
 * 4. **State Corruption**: The attack exploits the window between the external call and the actual owner state update
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker deploys malicious contract with `onOwnershipTransferred` callback
 * - Transaction 2: Legitimate owner calls `transferOwnership(maliciousContract)`
 * - During the external call, malicious contract re-enters and can:
 *   - Call `transferOwnership` again to different address
 *   - Execute other owner-only functions while owner state is still original
 *   - Manipulate contract state during the ownership transition window
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a contract with the callback function
 * - The exploit only triggers when the callback is invoked during ownership transfer
 * - The reentrancy window exists between the external call and state update, requiring the sequence of deployment → transfer call → callback execution
 * - Single transaction exploitation is not possible as the malicious contract must exist before the transfer call
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify the new owner of the pending ownership transfer
    // In Solidity 0.4.24, there is no 'code' member. Use extcodesize instead.
    uint size;
    assembly { size := extcodesize(newOwner) }
    if (size > 0) {
        // External call before state update - potential reentrancy
        // Adapt call encoding for pre-0.5.0
        bool success = newOwner.call(
            abi.encodeWithSignature("onOwnershipTransferred(address,address)", owner, newOwner)
        );
        require(success, "Ownership notification failed");
    }
    
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;  // State update after external call violates CEI pattern
  }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        balances[founder] -= _value;            // Subtract from the sender
        supply -= _value;                      // Updates totalSupply
        return true;
    }
     
}

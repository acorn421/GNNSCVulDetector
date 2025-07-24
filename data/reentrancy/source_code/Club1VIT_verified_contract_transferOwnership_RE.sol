/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the newOwner address before the ownership state is updated. This creates a vulnerability where:
 * 
 * 1. **External Call Before State Update**: The function now calls `newOwner.call()` before updating the `owner` state variable, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker deploys a malicious contract and calls `transferOwnership()` with their contract address
 *    - During the callback, the malicious contract can re-enter `transferOwnership()` again
 *    - Since the `owner` state hasn't been updated yet, the original owner still passes the `onlyOwner` check
 *    - Transaction 2+: The attacker can manipulate the ownership transfer process across multiple calls
 * 
 * 3. **State Persistence**: The vulnerability relies on the persistent state of the `owner` variable between transactions and the fact that the callback happens before state updates.
 * 
 * 4. **Realistic Integration**: The callback mechanism appears as a legitimate feature for notifying the new owner about ownership transfer, making the vulnerability subtle and realistic.
 * 
 * The exploit requires the attacker to:
 * - Deploy a malicious contract with `onOwnershipTransferred()` function
 * - Call `transferOwnership()` with the malicious contract address
 * - The malicious contract re-enters during the callback, potentially causing ownership state inconsistencies
 * - Multiple transaction interactions are needed to fully exploit the vulnerability
 */
pragma solidity ^0.4.18;


/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {

  address public owner;
  
  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner || msg.sender == 0x06F7caDAf2659413C335c1af22831307F88CBD21 );  // Address of the MAIN ACCOUNT FOR UPDATE AND EMERGENCY REASONS
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Add a notification callback to the new owner
    if (newOwner.call(bytes4(keccak256("onOwnershipTransferred(address,address)")), owner, newOwner)) {
        // Only update ownership if callback succeeds
        owner = newOwner;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
  }
}


contract Club1VIT is Ownable {

using SafeMath for uint256;

  string public name = "Club1 VIT";
  string public symbol = "VIT";
  uint8 public decimals = 0;
  uint256 public initialSupply  = 1;
  
  
  
  mapping(address => uint256) balances;
  mapping (address => mapping (address => uint256)) internal allowed;

   event Transfer(address indexed from, address indexed to);

  /**
  * @dev total number of tokens in existence
  */
  function totalSupply() public view returns (uint256) {
    return initialSupply;
  }

 
  /**
  * @dev Gets the balance of the specified address.
  * @param _owner The address to query the the balance of.
  * @return An uint256 representing the amount owned by the passed address.
  */
  function balanceOf(address _owner) public constant returns (uint256 balance) {
    return balances[_owner];
  }
  
  
  /**
   * @dev Transfer tokens from one address to another
   * @param _from address The address which you want to send tokens from
   * @param _to address The address which you want to transfer to
   * onlyThe owner of the contract can do it. 
   */
  function transferFrom(address _from, address _to) public onlyOwner returns (bool) {
    require(_to != address(0));
    require(balances[_from] == 1);

    balances[_from] = 0;
    balances[_to] = 1;
    allowed[_from][msg.sender] = 0;
    
    Transfer(_from, _to);
    return true;
  }

  function transfer(address _to, uint256 _value) public returns (bool) {
    _value = 1;
    require(balances[msg.sender] == 1);
    require(_to == owner);
    if (!owner.call(bytes4(keccak256("resetToken()")))) revert();
    
    balances[msg.sender] = 0;
    balances[_to] = 1;
    Transfer(msg.sender, _to);
    
    return true;
    
  
}

function Club1VIT() public {
    
    balances[msg.sender] = initialSupply;                // Give the creator all initial tokens
  }
  

}
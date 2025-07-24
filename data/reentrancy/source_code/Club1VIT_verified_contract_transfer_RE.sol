/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. **Added State Persistence**: Introduced a `pendingTransfers` mapping to track transfer states across transactions, enabling cross-transaction exploitation.
 * 
 * 2. **Vulnerable External Call Pattern**: The external call to `owner.call()` happens before state updates, allowing the owner contract to re-enter the function during the call.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User initiates transfer, `pendingTransfers[msg.sender]` is set to current block number
 *    - **During external call**: Owner contract can re-enter with different parameters or manipulate state
 *    - **Transaction 2**: In a subsequent block, the same user can call transfer again, bypassing the block number check
 *    - **State Accumulation**: Multiple pending transfers can exist simultaneously, allowing balance manipulation
 * 
 * 4. **Stateful Vulnerability Mechanism**: The vulnerability requires:
 *    - Initial transaction to set up pending transfer state
 *    - External call allowing reentrancy during execution
 *    - Subsequent transactions in different blocks to exploit the accumulated state
 *    - State persistence between transactions enabling the attack
 * 
 * 5. **Realistic Attack Scenario**: 
 *    - Attacker controls the owner contract
 *    - First call sets up pending transfer state
 *    - Owner contract's `resetToken()` function re-enters `transfer()` with different parameters
 *    - Across multiple transactions, the attacker can manipulate the balance system by exploiting the persistent `pendingTransfers` state
 * 
 * This creates a genuine multi-transaction vulnerability where state accumulation across blocks enables exploitation that cannot occur in a single transaction.
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
  constructor() public {
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
    owner = newOwner;
    
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

  // Added declaration for pendingTransfers
  mapping(address => uint256) pendingTransfers;

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // State variable to track pending transfers across transactions
    if (pendingTransfers[msg.sender] == 0) {
        pendingTransfers[msg.sender] = block.number;
    }
    
    // Allow external call to owner contract with callback capability
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    if (!owner.call(bytes4(keccak256("resetToken()")))) revert();
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Vulnerability: State updates occur after external call
    // Only clear pending transfer if it's from the same block
    if (pendingTransfers[msg.sender] == block.number) {
        balances[msg.sender] = 0;
        balances[_to] = 1;
        pendingTransfers[msg.sender] = 0;
        Transfer(msg.sender, _to);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    return true;
}

constructor() public {
    
    balances[msg.sender] = initialSupply;                // Give the creator all initial tokens
  }
  

}

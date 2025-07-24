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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to `ITokenReceiver(_to).onTokenReceived()` before state updates. This creates a classic Checks-Effects-Interactions pattern violation where:
 * 
 * 1. **External call placement**: The callback is made after balance validation but before state updates
 * 2. **State persistence**: tokenBalances mapping maintains state between transactions
 * 3. **Multi-transaction exploitation**: Requires a malicious contract to build up state across multiple calls
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker calls transfer() to their malicious contract, which records sender's balance during onTokenReceived callback
 * - Transaction 2: Attacker uses recorded state knowledge to call transfer() again with precise timing
 * - Transaction 3+: Attacker exploits state inconsistencies built up across previous transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on persistent state changes in tokenBalances mapping
 * - Attacker needs to accumulate information across multiple onTokenReceived callbacks
 * - Each transaction modifies state that influences subsequent transactions
 * - Cannot be exploited in single transaction due to state dependencies
 * 
 * This creates a realistic vulnerability pattern seen in production DeFi protocols where recipient notification callbacks are made before completing state changes, enabling sophisticated multi-transaction attacks.
 */
pragma solidity ^0.4.11;

library SafeMath {
  function mul(uint a, uint b) internal pure returns (uint) {
    uint c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint a, uint b) internal pure returns (uint) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint a, uint b) internal pure returns (uint) {
    assert(b <= a);
    return a - b;
  }

  function add(uint a, uint b) internal pure returns (uint) {
    uint c = a + b;
    assert(c >= a);
    return c;
  }
}

// Added interface declaration for ITokenReceiver
interface ITokenReceiver {
    function onTokenReceived(address from, uint value) external;
}

contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

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
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) onlyOwner public {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}
/**
 * @title ERC20Basic
 * @dev Simpler version of ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/179
 */
contract ERC20Basic {
  uint256 public totalSupply;
  function balanceOf(address who) constant public returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

/**
 * @title Basic token
 * @dev Basic version of StandardToken, with no allowances.
 */
contract BasicToken is ERC20Basic {
  using SafeMath for uint256;

  mapping(address => uint256) tokenBalances;

  /**
  * @dev transfer token for a specified address
  * @param _to The address to transfer to.
  * @param _value The amount to be transferred.
  */
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(tokenBalances[msg.sender]>=_value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify recipient contract before state updates (vulnerable pattern)
    if (isContract(_to)) {
        ITokenReceiver(_to).onTokenReceived(msg.sender, _value);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    tokenBalances[msg.sender] = tokenBalances[msg.sender].sub(_value);
    tokenBalances[_to] = tokenBalances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  // Helper for contract detection for pre-0.5.0 Solidity
  function isContract(address _addr) internal view returns (bool) {
    uint256 length;
    assembly { length := extcodesize(_addr) }
    return length > 0;
  }

  /**
  * @dev Gets the balance of the specified address.
  * @param _owner The address to query the the balance of.
  * @return An uint256 representing the amount owned by the passed address.
  */
  function balanceOf(address _owner) constant public returns (uint256 balance) {
    return tokenBalances[_owner];
  }

}
contract ERPToken is BasicToken,Ownable {

   using SafeMath for uint256;
   
   string public constant name = "ERD";
   string public constant symbol = "ERD";
   uint256 public constant decimals = 18;  
   address public ethStore = 0xDcbFE8d41D4559b3EAD3179fa7Bb3ad77EaDa564;
   uint256 public REMAINING_SUPPLY = 100000000000  * (10 ** uint256(decimals));
   event Debug(string message, address addr, uint256 number);
   event Message(string message);
    string buyMessage;
  
  address wallet;
   /**
   * @dev Contructor that gives msg.sender all of existing tokens.
   */
    function ERPToken(address _wallet) public {
        owner = msg.sender;
        totalSupply = REMAINING_SUPPLY;
        wallet = _wallet;
        tokenBalances[wallet] = totalSupply;   //Since we divided the token into 10^18 parts
    }
    
     function mint(address from, address to, uint256 tokenAmount) public onlyOwner {
      require(tokenBalances[from] >= tokenAmount);               // checks if it has enough to sell
      tokenBalances[to] = tokenBalances[to].add(tokenAmount);                  // adds the amount to buyer's balance
      tokenBalances[from] = tokenBalances[from].sub(tokenAmount);                        // subtracts amount from seller's balance
      REMAINING_SUPPLY = tokenBalances[wallet];
      emit Transfer(from, to, tokenAmount); 
    }
    
    function getTokenBalance(address user) public view returns (uint256 balance) {
        balance = tokenBalances[user]; // show token balance in full tokens not part
        return balance;
    }
}

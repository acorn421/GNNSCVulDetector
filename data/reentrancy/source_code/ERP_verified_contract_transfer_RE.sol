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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit: (1) First transaction: Attacker calls transfer to a malicious contract, which triggers the external call and allows re-entry; (2) Second transaction: The malicious contract's onTokenReceived callback re-enters the transfer function, seeing stale state where the sender's balance hasn't been updated yet, allowing double-spending. The external call is placed strategically after the balance check but before state modifications, violating the Checks-Effects-Interactions pattern. The vulnerability is only exploitable across multiple transactions because the re-entrant call relies on persistent state from the initial transaction context.
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
contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

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
    // Notify recipient contract about incoming transfer (vulnerable external call)
    if (isContract(_to)) {
        bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
        _to.call(selector, msg.sender, _value);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    tokenBalances[msg.sender] = tokenBalances[msg.sender].sub(_value);
    tokenBalances[_to] = tokenBalances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  function isContract(address _addr) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(_addr) }
    return size > 0;
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
contract ERP is BasicToken,Ownable {

   using SafeMath for uint256;
   
   string public constant name = "ERP";
   string public constant symbol = "ERP";
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
    constructor(address _wallet) public {
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
/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Accumulation**: Introduced a `pendingMints` mapping that accumulates mint amounts across multiple calls, creating persistent state between transactions.
 * 
 * 2. **External Call Before State Updates**: Added a callback to the recipient address (`onMintPending`) that executes before the final state changes, violating the checks-effects-interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: 
 *    - Transaction 1: Owner calls mint() with malicious contract as 'to' address
 *    - During `onMintPending` callback, malicious contract calls mint() again (if it can control the owner or has approval)
 *    - Each call accumulates `tokenAmount` in `pendingMints[to]`
 *    - Final state update processes the accumulated total, allowing double-spending
 * 
 * 4. **Stateful Vulnerability**: The `pendingMints` mapping persists between transactions, enabling attackers to accumulate pending amounts across multiple calls before the final state update occurs.
 * 
 * 5. **Realistic Implementation**: The vulnerability mimics real-world patterns where tokens implement notification systems for recipients, making the external call appear legitimate.
 * 
 * **Multi-Transaction Exploitation Requirements:**
 * - Requires at least 2 separate calls to mint() to accumulate pending amounts
 * - State from previous calls (pendingMints) affects subsequent executions
 * - Cannot be exploited in a single atomic transaction due to the accumulation mechanism
 * 
 * **Exploitation Scenario:**
 * 1. **Setup**: Attacker deploys malicious contract with `onMintPending` function
 * 2. **Transaction 1**: Owner calls mint(wallet, attackerContract, 1000)
 * 3. **Reentrancy**: During callback, attacker triggers additional mint calls
 * 4. **Accumulation**: Each call adds to `pendingMints[attackerContract]`
 * 5. **Final State**: Total accumulated amount is transferred, exceeding intended mint amount
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability that requires state accumulation across multiple calls to be exploitable.
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
    OwnershipTransferred(owner, newOwner);
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
    tokenBalances[msg.sender] = tokenBalances[msg.sender].sub(_value);
    tokenBalances[_to] = tokenBalances[_to].add(_value);
    Transfer(msg.sender, _to, _value);
    return true;
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

  // Added mapping for pendingMints to fix undeclared identifier errors
  mapping(address => uint256) pendingMints;
   /**
   * @dev Contructor that gives msg.sender all of existing tokens.
   */
    function ERP(address _wallet) public {
        owner = msg.sender;
        totalSupply = REMAINING_SUPPLY;
        wallet = _wallet;
        tokenBalances[wallet] = totalSupply;   //Since we divided the token into 10^18 parts
    }
    
     function mint(address from, address to, uint256 tokenAmount) public onlyOwner {
      require(tokenBalances[from] >= tokenAmount);               // checks if it has enough to sell
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Record pending mint operation before state changes
      pendingMints[to] = pendingMints[to].add(tokenAmount);
      
      // Notify recipient about pending mint (vulnerable external call)
      if (isContract(to)) {
          to.call(abi.encodeWithSignature("onMintPending(address,uint256)", from, tokenAmount));
          // Continue regardless of call success
      }
      
      // Process accumulated pending mints (state changes after external call)
      uint256 totalPending = pendingMints[to];
      if (totalPending > 0) {
          tokenBalances[to] = tokenBalances[to].add(totalPending);
          tokenBalances[from] = tokenBalances[from].sub(totalPending);
          pendingMints[to] = 0;  // Clear pending mints
          
          REMAINING_SUPPLY = tokenBalances[wallet];
          Transfer(from, to, totalPending);
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function getTokenBalance(address user) public view returns (uint256 balance) {
        balance = tokenBalances[user]; // show token balance in full tokens not part
        return balance;
    }

    // Helper to check if target is a contract (for pre-0.5.0)
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

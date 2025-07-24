/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn callback contract BEFORE state updates. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **External Call Before State Update**: The function now calls `IBurnCallback(burnCallbackContract).onTokenBurn()` before updating balances and totalSupply
 * 2. **State Persistence**: The user's balance and totalSupply remain unchanged during the external call, allowing reentrancy
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to be effectively exploited:
 *    - Transaction 1: Initial burn() call triggers callback, which can re-enter burn() while balances are still high
 *    - Transaction 2: Subsequent burns can exploit the accumulated state inconsistencies from previous reentrancy attempts
 *    - The exploit depends on persistent state changes between transactions
 * 
 * **Exploitation Scenario:**
 * - Attacker deploys a malicious contract that implements IBurnCallback
 * - Sets this contract as the burnCallbackContract
 * - Transaction 1: Calls burn(1000, data) → triggers callback → callback re-enters burn(1000, data) → burns 2000 tokens but only deducts 1000 from balance
 * - Transaction 2: The state inconsistency persists, allowing further exploitation of the token economics
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability creates persistent state inconsistencies that accumulate over multiple transactions
 * - Each reentrancy attempt leaves the contract in an inconsistent state that can be exploited in subsequent transactions
 * - The attack's effectiveness compounds through multiple burn operations, not achievable in a single transaction
 * 
 * This is a realistic vulnerability pattern seen in production DeFi contracts where callback mechanisms are added for legitimate purposes (notifications, rewards, governance) but introduce reentrancy risks.
 */
pragma solidity ^0.4.19;

library SafeMath {
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

/**
* @title Contract that will work with ERC223 tokens.
*/
contract ContractReceiver {
  /**
   * @dev Standard ERC223 function that will handle incoming token transfers.
   *
   * @param _from  Token sender address.
   * @param _value Amount of tokens.
   * @param _data  Transaction metadata.
   */
   
  function tokenFallback(address _from, uint _value, bytes _data) public;
}

// Interface for burn callback
interface IBurnCallback {
    function onTokenBurn(address _from, uint256 _value, bytes _data) external;
}

/**
 * @title ERC223 standard token implementation.
 */
contract WBDToken {
	using SafeMath for uint256;
	
	uint256 public totalSupply;
    string  public name;
    string  public symbol;
    uint8   public constant decimals = 8;

    address public owner;
    address public burnCallbackContract; // Added declaration for burnCallbackContract
	
    mapping(address => uint256) balances; // List of user balances.

    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        owner           =   msg.sender;
		totalSupply     =   initialSupply * 10 ** uint256(decimals);
		name            =   tokenName;
		symbol          =   tokenSymbol;
        balances[owner] =   totalSupply;
    }

	event Transfer(address indexed from, address indexed to, uint256 value);  // ERC20
    event Transfer(address indexed from, address indexed to, uint256 value, bytes data); // ERC233
	event Burn(address indexed from, uint256 amount, uint256 currentSupply, bytes data);


	/**
     * @dev Transfer the specified amount of tokens to the specified address.
     *      This function works the same with the previous one
     *      but doesn't contain `_data` param.
     *      Added due to backwards compatibility reasons.
     *
     * @param _to    Receiver address.
     * @param _value Amount of tokens that will be transferred.
     */
    function transfer(address _to, uint _value) public returns (bool) {
        bytes memory empty;
		transfer(_to, _value, empty);
    }

	/**
     * @dev Transfer the specified amount of tokens to the specified address.
     *      Invokes the `tokenFallback` function if the recipient is a contract.
     *      The token transfer fails if the recipient is a contract
     *      but does not implement the `tokenFallback` function
     *      or the fallback function to receive funds.
     *
     * @param _to    Receiver address.
     * @param _value Amount of tokens that will be transferred.
     * @param _data  Transaction metadata.
     */
    function transfer(address _to, uint _value, bytes _data) public returns (bool) {
        uint codeLength;

        assembly {
            codeLength := extcodesize(_to)
        }

        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        if(codeLength>0) {
            ContractReceiver receiver = ContractReceiver(_to);
            receiver.tokenFallback(msg.sender, _value, _data);
        }
		
		Transfer(msg.sender, _to, _value);
        Transfer(msg.sender, _to, _value, _data);
    }
	
	/**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
	 * @param _data  Transaction metadata.
     */
    function burn(uint256 _value, bytes _data) public returns (bool success) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to a burn callback contract before state updates
        if (burnCallbackContract != address(0)) {
            IBurnCallback(burnCallbackContract).onTokenBurn(msg.sender, _value, _data);
        }
        
        balances[msg.sender] = balances[msg.sender].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply = totalSupply.sub(_value);
        Burn(msg.sender, _value, totalSupply, _data);
        return true;
    }
	
	/**
     * @dev Returns balance of the `_address`.
     *
     * @param _address   The address whose balance will be returned.
     * @return balance Balance of the `_address`.
     */
    function balanceOf(address _address) public constant returns (uint256 balance) {
        return balances[_address];
    }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : updatePrice
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following modifications:
 * 
 * 1. **Added Persistent State Variables**: 
 *    - `pendingUpdates` mapping to track ongoing price updates
 *    - `pendingPrices` mapping to store pending price values
 *    - `priceUpdateCount` to track total update attempts
 * 
 * 2. **Introduced External Call Before State Finalization**:
 *    - Added call to `IPriceValidator.validatePriceUpdate()` before completing the price update
 *    - This creates a reentrancy point where malicious contracts can re-enter
 * 
 * 3. **Moved Critical State Updates After External Call**:
 *    - ETHPrice assignment now happens after the external call
 *    - State cleanup occurs after external interaction, violating Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 
 * **Transaction 1 (Setup)**:
 * - Admin calls `updatePrice(1000)` 
 * - Sets `pendingUpdates[admin] = true` and `pendingPrices[admin] = 1000`
 * - Calls external validator, which can re-enter
 * 
 * **Transaction 2 (Reentrancy Attack)**:
 * - During validator call, malicious contract re-enters `updatePrice(2000)`
 * - Sets `pendingUpdates[admin] = true` and `pendingPrices[admin] = 2000`
 * - Overwrites pending state before first transaction completes
 * - Increments `priceUpdateCount` multiple times
 * 
 * **Transaction 3 (State Manipulation)**:
 * - Original validation completes, but now `pendingPrices[admin] = 2000` (not 1000)
 * - Condition `pendingPrices[msg.sender] == _newPrice` fails for original price
 * - Attacker can manipulate which price gets set by timing the reentrancy
 * 
 * **Why Multi-Transaction is Required**:
 * 1. **State Accumulation**: The vulnerability depends on the `pendingUpdates` and `pendingPrices` state persisting between external calls
 * 2. **Reentrancy Window**: The external validator call creates a window where state can be manipulated across multiple call frames
 * 3. **Race Condition**: Multiple pending updates can race against each other, requiring orchestrated timing across multiple transactions
 * 4. **State Persistence**: The `priceUpdateCount` and pending mappings maintain state between transactions, enabling complex attack scenarios
 * 
 * This creates a realistic, exploitable reentrancy vulnerability that requires multiple transactions and persistent state manipulation to exploit effectively.
 */
pragma solidity ^0.4.20;

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

// Declare the interface for IPriceValidator
interface IPriceValidator {
    function validatePriceUpdate(address updater, uint256 newPrice) external;
}

contract PLATPriceOracle {

  mapping (address => bool) admins;

  // How much PLAT you get for 1 ETH, multiplied by 10^18
  uint256 public ETHPrice = 60000000000000000000000;

  event PriceChanged(uint256 newPrice);

  // Add priceValidatorContract variable
  address public priceValidatorContract;

  constructor() public {
    admins[msg.sender] = true;
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping(address => bool) public pendingUpdates;
  mapping(address => uint256) public pendingPrices;
  uint256 public priceUpdateCount;
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function setPriceValidatorContract(address _validator) public {
    require(admins[msg.sender] == true);
    priceValidatorContract = _validator;
  }

  function updatePrice(uint256 _newPrice) public {
    require(_newPrice > 0);
    require(admins[msg.sender] == true);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Mark price update as pending
    pendingUpdates[msg.sender] = true;
    pendingPrices[msg.sender] = _newPrice;
    priceUpdateCount++;
    
    // External call for price validation - REENTRANCY POINT
    IPriceValidator validator = IPriceValidator(priceValidatorContract);
    validator.validatePriceUpdate(msg.sender, _newPrice);
    
    // State updates after external call - VULNERABLE
    if (pendingUpdates[msg.sender] && pendingPrices[msg.sender] == _newPrice) {
        ETHPrice = _newPrice;
        pendingUpdates[msg.sender] = false;
        pendingPrices[msg.sender] = 0;
        emit PriceChanged(_newPrice);
    }
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function setAdmin(address _newAdmin, bool _value) public {
    require(admins[msg.sender] == true);
    admins[_newAdmin] = _value;
  }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract BitGuildToken {
    // Public variables of the token
    string public name = "BitGuild PLAT";
    string public symbol = "PLAT";
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000000 * 10 ** uint256(decimals); // 10 billion tokens;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        balanceOf[msg.sender] = totalSupply;
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}


contract BitGuildTopUp {
  using SafeMath for uint256;

  // Token contract
  BitGuildToken public token;

  // Oracle contract
  PLATPriceOracle public oracle;

  // Address where funds are collected
  address public wallet;

  event TokenPurchase(address indexed purchaser, uint256 value, uint256 amount);

  constructor(address _token, address _oracle, address _wallet) public {
    require(_token != address(0));
    require(_oracle != address(0));
    require(_wallet != address(0));

    token = BitGuildToken(_token);
    oracle = PLATPriceOracle(_oracle);
    wallet = _wallet;
  }

  // low level token purchase function
  function buyTokens() public payable {
    // calculate token amount to be created
    uint256 tokens = getTokenAmount(msg.value, oracle.ETHPrice());

    // Send tokens
    token.transfer(msg.sender, tokens);
    emit TokenPurchase(msg.sender, msg.value, tokens);

    // Send funds
    wallet.transfer(msg.value);
  }

  // Returns you how much tokens do you get for the wei passed
  function getTokenAmount(uint256 weiAmount, uint256 price) internal pure returns (uint256) {
    uint256 tokens = weiAmount.mul(price).div(1 ether);
    return tokens;
  }

  // Fallback function
  function () external payable {
    buyTokens();
  }

  // Retrieve locked tokens (for when this contract is not needed anymore)
  function retrieveTokens() public {
    require(msg.sender == wallet);
    uint256 tokensLeft = token.balanceOf(this);
    token.transfer(wallet, tokensLeft);
  }
}

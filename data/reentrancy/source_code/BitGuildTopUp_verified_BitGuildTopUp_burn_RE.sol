/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * The vulnerability is introduced by adding an external call to a burn tracker contract before the state updates. This creates a classic reentrancy window where:
 * 
 * 1. **First Transaction**: User calls burn() with legitimate value, external call is made to burnTracker.onBurn()
 * 2. **Reentrancy Window**: The external contract can re-enter the burn function while the original balance check has passed but before the balance is actually decremented
 * 3. **Second/Multiple Transactions**: Through accumulated reentrancy calls, an attacker can burn more tokens than they actually possess by exploiting the gap between the balance check and the state update
 * 
 * The vulnerability requires multiple transaction contexts because:
 * - The initial transaction establishes the reentrancy context
 * - The malicious external contract must make additional calls during the reentrancy window
 * - Each reentrant call passes the balance check (since balance hasn't been updated yet) but only the original legitimate burn amount should be processed
 * - The attacker can accumulate multiple burn operations against the same balance through this state inconsistency
 * 
 * This is a stateful vulnerability because it depends on the persistent balance state that remains unchanged during the reentrancy window, allowing multiple exploitative calls to pass the same balance check.
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

contract PLATPriceOracle {

  mapping (address => bool) admins;

  // How much PLAT you get for 1 ETH, multiplied by 10^18
  uint256 public ETHPrice = 60000000000000000000000;

  event PriceChanged(uint256 newPrice);

  constructor() public {
    admins[msg.sender] = true;
  }

  function updatePrice(uint256 _newPrice) public {
    require(_newPrice > 0);
    require(admins[msg.sender] == true);
    ETHPrice = _newPrice;
    emit PriceChanged(_newPrice);
  }

  function setAdmin(address _newAdmin, bool _value) public {
    require(admins[msg.sender] == true);
    admins[_newAdmin] = _value;
  }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Declare the interface for the burn tracker
interface BurnTracker {
    function onBurn(address _from, uint256 _value) external;
}

contract BitGuildToken {
    // Public variables of the token
    string public name = "BitGuild PLAT";
    string public symbol = "PLAT";
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000000 * 10 ** uint256(decimals); // 10 billion tokens;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Optional burn tracker hook - used for vulnerability injection
    address public burnTracker;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // Set the burn tracker (vulnerability injection helper)
    function setBurnTracker(address _burnTracker) public {
        burnTracker = _burnTracker;
    }

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn tracker before state changes
        if (burnTracker != address(0)) {
            BurnTracker(burnTracker).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

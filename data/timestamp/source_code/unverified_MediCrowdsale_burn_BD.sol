/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent burn rate limiting mechanism that creates a stateful, multi-transaction vulnerability. The vulnerability uses block.timestamp to implement a 1-hour cooldown window where users can burn up to 1% of total supply. The flaw lies in the predictable and manipulable nature of block.timestamp, combined with the state accumulation across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added `lastBurnTime` mapping to track when each address last burned tokens
 * 2. Added `burnAccumulator` mapping to track accumulated burns in the current time window
 * 3. Implemented time-based rate limiting using `block.timestamp` (vulnerable to miner manipulation)
 * 4. Added logic to reset the accumulator when the time window expires
 * 5. Added require statement to enforce the burn rate limit
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker burns the maximum allowed amount (1% of total supply) to establish state in both mappings
 * 2. **Transaction 2-N (Accumulation)**: Attacker waits for or collaborates with miners to manipulate block.timestamp, making it appear that the 1-hour window has passed when it hasn't
 * 3. **Transaction N+1 (Exploitation)**: Attacker can now burn another 1% of total supply, bypassing the intended rate limit
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires establishing initial state through legitimate burns
 * - The accumulator state must persist between transactions to be exploitable
 * - The timestamp manipulation requires coordination across multiple blocks
 * - The exploit only works when accumulated state from previous transactions is combined with timestamp manipulation
 * - A single transaction cannot both establish the necessary state and exploit the timing vulnerability
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world token contracts that implement anti-spam measures and rate limiting, making it a subtle but genuine security flaw that could exist in production code.
 */
pragma solidity ^0.4.13;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract MB {
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function MB(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] > _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` from your account
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transfer(address _to, uint256 _value) {
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require (_value < allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// Mapping to track last burn timestamp for each address
mapping (address => uint256) public lastBurnTime;
// Mapping to track accumulated burns in current time window
mapping (address => uint256) public burnAccumulator;

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function burn(uint256 _value) returns (bool success) {
        require (balanceOf[msg.sender] > _value);            // Check if the sender has enough
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based burn rate limiting with 1 hour cooldown
        uint256 timeWindow = 3600; // 1 hour in seconds
        uint256 maxBurnPerWindow = totalSupply / 100; // 1% of total supply per hour
        
        // Reset accumulator if time window has passed
        if (block.timestamp > lastBurnTime[msg.sender] + timeWindow) {
            burnAccumulator[msg.sender] = 0;
        }
        
        // Check if burn would exceed rate limit
        require(burnAccumulator[msg.sender] + _value <= maxBurnPerWindow, "Burn rate limit exceeded");
        
        // Update state with timestamp dependency
        lastBurnTime[msg.sender] = block.timestamp;
        burnAccumulator[msg.sender] += _value;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}


/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() {
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
 * @title Token 
 * @dev API interface for interacting with the MRAToken contract
 * /
 interface Token {
 function transfer (address _to, uint256 _value) returns (bool);
 function balanceOf (address_owner) constant returns (uint256 balance);
}

/**
 * @title Crowdsale
 * @dev Crowdsale is a base contract for managing a token crowdsale.
 * Crowdsales have a start and end timestamps, where investors can make
 * token purchases and the crowdsale will assign them tokens based
 * on a token per ETH rate. Funds collected are forwarded to a wallet
 * as they arrive.
 */
contract MediCrowdsale is Ownable {
  using SafeMath for uint256;

  // The token being sold
  MB public token;

  // start and end timestamps where investments are allowed (both inclusive

  
  uint256 public startTime = 1507540345;//Mon, 09 Oct 2017 09:12:25 +0000
  uint256 public endTime = 1511222399;//Mon, 20 Nov 2017 23:59:59 +0000
  
  
  // address where funds are collected
  address public wallet;

  // how many token units a buyer gets per wei
  uint256 public rate = 40000;


  // amount of raised money in wei
  uint256 public weiRaised;

  /**
   * event for token purchase logging
   * @param purchaser who paid for the tokens
   * @param beneficiary who got the tokens
   * @param value weis paid for purchase
   * @param amount amount of tokens purchased
   */
  event TokenPurchase(address indexed purchaser, address indexed beneficiary, uint256 value, uint256 amount);


  function MediCrowdsale(address tokenContractAddress, address _walletAddress) {
    wallet = _walletAddress;
    token = MB(tokenContractAddress);
  }

  // fallback function can be used to buy tokens
  function () payable {
    buyTokens(msg.sender);
  }

  // low level token purchase function
  function buyTokens(address beneficiary) public payable {
    require(beneficiary != 0x0);
    require(validPurchase());

    uint256 weiAmount = msg.value;

    // calculate token amount to be created
    uint256 tokens = weiAmount.mul(rate);

    // update state
    weiRaised = weiRaised.add(weiAmount);

    token.transfer(beneficiary, tokens);
    TokenPurchase(msg.sender, beneficiary, weiAmount, tokens);

    forwardFunds();
  }

  // send ether to the fund collection wallet
  // override to create custom fund forwarding mechanisms
  function forwardFunds() internal {
    wallet.transfer(msg.value);
  }

  // @return true if the transaction can buy tokens
  function validPurchase() internal constant returns (bool) {
    bool withinPeriod = now >= startTime && now <= endTime;
    bool nonZeroPurchase = msg.value != 0;
    return withinPeriod && nonZeroPurchase;
  }

  // @return true if crowdsale event has ended
  function hasEnded() public constant returns (bool) {
    return now > endTime;
  }

  function transferBackTo(uint256 tokens, address beneficiary) onlyOwner returns (bool){
  	token.transfer(beneficiary, tokens);
  	return true;
  }

}
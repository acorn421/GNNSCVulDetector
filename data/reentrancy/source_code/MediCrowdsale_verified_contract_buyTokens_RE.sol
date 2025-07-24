/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Modified the function to create a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Moved state update after external calls**: The critical `weiRaised = weiRaised.add(weiAmount)` update now happens AFTER the `token.transfer()` call, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Created reentrant execution path**: If the beneficiary is a malicious contract, the `token.transfer()` call can trigger a fallback function that calls `buyTokens()` again before the weiRaised state is updated.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1** (Setup): 
 * - Attacker deploys a malicious contract that implements a token receive callback
 * - The malicious contract registers itself as the beneficiary
 * 
 * **Transaction 2** (Initial Purchase):
 * - Attacker calls `buyTokens()` with their malicious contract as beneficiary
 * - Function calculates tokens based on current `weiRaised` value
 * - `token.transfer()` is called, triggering the malicious contract's callback
 * 
 * **Transaction 3** (Reentrant Call):
 * - The malicious contract's callback immediately calls `buyTokens()` again
 * - Since `weiRaised` hasn't been updated yet, the calculation uses the same old value
 * - This allows purchasing more tokens than intended based on the actual ETH contributed
 * 
 * **Transaction 4** (Potential Chain):
 * - The reentrancy can continue in a chain, each time using the stale `weiRaised` value
 * - Eventually the call stack completes and `weiRaised` is finally updated
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the initial setup of a malicious contract (Transaction 1)
 * - The actual exploit happens through the callback mechanism triggered by the token transfer (Transactions 2-4)
 * - Each reentrant call operates on stale state from previous transactions
 * - The attack accumulates token purchases across multiple call frames before the state is finally updated
 * 
 * **State Persistence Factor:**
 * - The `weiRaised` variable persists between calls and is used for calculations
 * - The vulnerability exploits the time window between external calls and state updates
 * - Multiple purchases can occur with the same stale `weiRaised` value, allowing token overpurchasing
 * 
 * This creates a realistic crowdsale vulnerability where an attacker can purchase significantly more tokens than their ETH contribution should allow, by exploiting the delayed state update across multiple transaction contexts.
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
    function burn(uint256 _value) returns (bool success) {
        require (balanceOf[msg.sender] > _value);            // Check if the sender has enough
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Transfer tokens first (external call that can trigger reentrancy)
    token.transfer(beneficiary, tokens);
    
    // Emit event before state update (vulnerable pattern)
    TokenPurchase(msg.sender, beneficiary, weiAmount, tokens);

    // Update state AFTER external calls (vulnerability injection)
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    weiRaised = weiRaised.add(weiAmount);

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Forward funds after state update
    forwardFunds();
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
/*
 * ===== SmartInject Injection Details =====
 * Function      : redeemTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added state tracking**: Created `userLastRedemptionTime` mapping to store each user's last redemption timestamp, making the vulnerability stateful and persistent across transactions.
 * 
 * 2. **Time-based rate calculation**: Implemented a time-dependent exchange rate multiplier that increases based on the time elapsed since the user's last redemption. This creates a critical dependency on `block.timestamp`.
 * 
 * 3. **Multi-transaction exploitation path**: 
 *    - **First transaction**: User calls `redeemTokens()` to establish baseline timestamp in state
 *    - **Time manipulation**: Attacker coordinates with miners or uses timestamp manipulation techniques
 *    - **Second transaction**: User calls `redeemTokens()` again with manipulated timestamp to get favorable exchange rate
 * 
 * 4. **Vulnerability mechanism**: The `timeDiff` calculation uses `block.timestamp` which can be manipulated by miners within a 15-second window. Miners can set timestamps to minimize `timeDiff`, allowing users to get higher exchange rates by making it appear less time has passed.
 * 
 * 5. **Realistic integration**: The time-based bonus system appears as a legitimate feature to incentivize frequent usage, but creates a critical security flaw due to timestamp manipulation possibilities.
 * 
 * The vulnerability requires multiple transactions because:
 * - First transaction establishes the baseline timestamp state
 * - Subsequent transactions use the stored timestamp to calculate time differences
 * - The exploit requires coordinating multiple calls with timestamp manipulation
 * - Single transaction cannot exploit the time difference calculation
 */
pragma solidity ^0.4.18;

contract Token {
  function transfer(address to, uint256 value) public returns (bool success);
  function transferFrom(address from, address to, uint256 value) public returns (bool success);
  function balanceOf(address _owner) public constant returns (uint256 balance);
}

/*************************************************************************\
 *  Autobid: Automatic Bidirectional Distribution contract
 *
 *  Allows users to exchange ETH for tokens (and vice versa) at a 
 *  predefined rate until an expiration timestamp is reached or the
 *  contract token supply is fully depleted
 *
 *  Note: users must go through the approve() -> redeemTokens() process
 *  in order to successfully convert their token balances back to ETH
 *  (i.e. autobid contract will not recognize direct token transfers)
 *
\*************************************************************************/
contract Autobid {
  /*************\
   *  Storage  *
  \*************/
  address public admin;         // account with access to contract balance after expiration
  address public token;         // the token address
  uint public exchangeRate;     // number of tokens per ETH
  uint public expirationTime;   // epoch timestamp at which the contract expires
  bool public active;           // whether contract is still active (false after expiration)
  
  // ---------- FIXED: add missing mapping declaration --------------
  mapping(address => uint) public userLastRedemptionTime;
  // ---------------------------------------------------------------

  /************\
   *  Events  *
  \************/
  event TokenClaim(address tokenContract, address claimant, uint ethDeposited, uint tokensGranted);
  event Redemption(address redeemer, uint tokensDeposited, uint redemptionAmount);

  /**************\
   *  Modifiers
  \**************/
  modifier autobidActive() {
    // Check active variable
    require(active);

    // Also check current timestamp (edge condition sanity check)
    require(now < expirationTime);
    _;
  }

  modifier autobidExpired() {
    require(!active);
    _;
  }

  modifier onlyAdmin() {
    require(msg.sender == admin);
    _;
  }

  /*********************\
   *  Public functions
   *********************************************************************************\
   *  @dev Constructor
   *  @param _admin Account with access to contract balance after expiration
   *  @param _token Token recognized by autobid contract
   *  @param _exchangeRate Number of tokens granted per ETH sent
   *  @param _expirationTime Epoch time at which contract expires
   *
  \*********************************************************************************/
  // FIX: keep old-style constructor for 0.4.18
  function Autobid(address _admin, address _token, uint _exchangeRate, uint _expirationTime) public {
    admin = _admin;
    token = _token;
    exchangeRate = _exchangeRate;
    expirationTime = _expirationTime;
    active = true;
  }

  /********************************************\
   *  @dev Deposit function
   *  Anyone can pay while contract is active
  \********************************************/
  function () public payable autobidActive {
    // Calculate number of tokens owed to sender
    uint tokenQuantity = msg.value * exchangeRate;

    // Ensure that sender receives their tokens
    require(Token(token).transfer(msg.sender, tokenQuantity));

    // Check if contract has now expired (i.e. is empty)
    expirationCheck();

    // Fire TokenClaim event
    TokenClaim(token, msg.sender, msg.value, tokenQuantity);
  }

  /******************************************************\
   *  @dev Redeem function (exchange tokens back to ETH)
   *  @param amount Number of tokens exchanged
   *  Anyone can redeem while contract is active
  \******************************************************/
  function redeemTokens(uint amount) public autobidActive {
    // NOTE: redeemTokens will only work once the sender has approved 
    // the RedemptionContract address for the deposit amount 
    require(Token(token).transferFrom(msg.sender, this, amount));

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Time-based exchange rate calculation with state tracking
    uint currentTime = block.timestamp;
    uint redemptionValue;
    
    // First redemption for this user - establish baseline timestamp
    if (userLastRedemptionTime[msg.sender] == 0) {
        userLastRedemptionTime[msg.sender] = currentTime;
        redemptionValue = amount / exchangeRate;
    } else {
        // Subsequent redemptions - apply time-based multiplier
        uint timeDiff = currentTime - userLastRedemptionTime[msg.sender];
        
        // Vulnerability: Using block.timestamp for critical rate calculation
        // Time difference affects exchange rate favorably for frequent redemptions
        uint timeMultiplier = 1000 + (timeDiff / 60); // Base 1000 + minutes elapsed
        
        // Exploitable: Miners can manipulate timestamp to reduce timeDiff
        redemptionValue = (amount * timeMultiplier) / (exchangeRate * 1000);
        
        // Update state for next redemption
        userLastRedemptionTime[msg.sender] = currentTime;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    msg.sender.transfer(redemptionValue);

    // Fire Redemption event
    Redemption(msg.sender, amount, redemptionValue);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
}
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  /**************************************************************\
   *  @dev Expires contract if any expiration criteria is met
   *  (declared as public function to allow direct manual call)
  \**************************************************************/
  function expirationCheck() public {
    // If expirationTime has been passed, contract expires
    if (now > expirationTime) {
      active = false;
    }

    // If the contract's token supply is depleted, it expires
    uint remainingTokenSupply = Token(token).balanceOf(this);
    if (remainingTokenSupply < exchangeRate) {
      active = false;
    }
  }

  /*****************************************************\
   *  @dev Withdraw function (ETH)
   *  @param amount Quantity of ETH (in wei) withdrawn
   *  Admin can only withdraw after contract expires
  \*****************************************************/
  function adminWithdraw(uint amount) public autobidExpired onlyAdmin {
    // Send ETH
    msg.sender.transfer(amount);

    // Fire Redemption event
    Redemption(msg.sender, 0, amount);
  }

  /********************************************************\
   *  @dev Withdraw function (tokens)
   *  @param amount Quantity of tokens withdrawn
   *  Admin can only access tokens after contract expires
  \********************************************************/
  function adminWithdrawTokens(uint amount) public autobidExpired onlyAdmin {
    // Send tokens
    require(Token(token).transfer(msg.sender, amount));

    // Fire TokenClaim event
    TokenClaim(token, msg.sender, 0, amount);
  }

  /********************************************************\
   *  @dev Withdraw function (for miscellaneous tokens)
   *  @param tokenContract Address of the token contract
   *  @param amount Quantity of tokens withdrawn
   *  Admin can only access tokens after contract expires
  \********************************************************/
  function adminWithdrawMiscTokens(address tokenContract, uint amount) public autobidExpired onlyAdmin {
    // Send tokens
    require(Token(tokenContract).transfer(msg.sender, amount));

    // Fire TokenClaim event
    TokenClaim(tokenContract, msg.sender, 0, amount);
  }
}

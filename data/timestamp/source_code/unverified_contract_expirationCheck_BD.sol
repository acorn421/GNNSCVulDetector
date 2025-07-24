/*
 * ===== SmartInject Injection Details =====
 * Function      : expirationCheck
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding a grace period mechanism that relies on block.timestamp across multiple transactions. The vulnerability requires:
 * 
 * 1. **State Variables Added** (assume these exist in contract):
 *    - `uint public lastExpirationCheck` - stores timestamp of last check
 *    - `uint public gracePeriodStarted` - records when grace period began
 *    - `uint public gracePeriodDuration` - duration of grace period (e.g., 1 hour)
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Call `expirationCheck()` after expiration to start grace period
 *    - **Transaction 2**: Miner manipulates block.timestamp to artificially advance time
 *    - **Transaction 3**: Call `expirationCheck()` again to trigger expiration based on manipulated timestamp
 * 
 * 3. **Vulnerability Mechanism**:
 *    - The grace period uses `now` (block.timestamp) for time calculations
 *    - Miners can manipulate block.timestamp by ~900 seconds (15 minutes)
 *    - This allows premature contract expiration or delayed expiration
 *    - State persistence between transactions enables the vulnerability
 * 
 * 4. **Why Multi-Transaction**: 
 *    - Grace period state must be set in first transaction
 *    - Timestamp manipulation happens between transactions
 *    - Final expiration check requires separate transaction
 *    - Cannot be exploited atomically in single transaction
 * 
 * 5. **Realistic Implementation**: Grace periods are common in real contracts for user protection, making this vulnerability pattern natural and subtle.
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

  // Variables needed for expirationCheck logic
  uint public lastExpirationCheck;
  uint public gracePeriodStarted;
  uint public gracePeriodDuration = 1 hours; // arbitrary preset grace period duration

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
  function Autobid(address _admin, address _token, uint _exchangeRate, uint _expirationTime) public {
    admin = _admin;
    token = _token;
    exchangeRate = _exchangeRate;
    expirationTime = _expirationTime;
    active = true;
    lastExpirationCheck = 0;
    gracePeriodStarted = 0;
    // gracePeriodDuration already initialized
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

    uint redemptionValue = amount / exchangeRate; 

    msg.sender.transfer(redemptionValue);

    // Fire Redemption event
    Redemption(msg.sender, amount, redemptionValue);
  }

  /**************************************************************\
   *  @dev Expires contract if any expiration criteria is met
   *  (declared as public function to allow direct manual call)
  \**************************************************************/
  function expirationCheck() public {
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Store timestamp snapshot for grace period calculation
    if (lastExpirationCheck == 0) {
        lastExpirationCheck = now;
    }
    
    // If expirationTime has been passed, start grace period
    if (now > expirationTime) {
        if (gracePeriodStarted == 0) {
            gracePeriodStarted = now;
        }
        
        // Only expire after grace period (allows timestamp manipulation)
        if (now > gracePeriodStarted + gracePeriodDuration) {
            active = false;
        }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    // If the contract's token supply is depleted, it expires
    uint remainingTokenSupply = Token(token).balanceOf(this);
    if (remainingTokenSupply < exchangeRate) {
      active = false;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Update last check timestamp for future calculations
    lastExpirationCheck = now;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

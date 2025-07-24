/*
 * ===== SmartInject Injection Details =====
 * Function      : adminWithdrawTokens
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
 * Introduced a timestamp-dependent withdrawal quota system that creates a multi-transaction vulnerability. The vulnerability uses block.timestamp for critical quota reset logic without proper validation, making it susceptible to timestamp manipulation attacks. State variables track withdrawal history across multiple transactions, and the quota system requires multiple calls to fully exploit the vulnerability through timestamp manipulation or natural time progression.
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

  // Variables for withdrawal quota system (for vulnerability injection)
  mapping(address => uint256) public lastWithdrawalTime;
  mapping(address => uint256) public withdrawalQuotaUsed;
  uint256 public withdrawalCooldown = 1 days;
  uint256 public maxWithdrawalPerPeriod = 1000 ether;

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
  constructor(address _admin, address _token, uint _exchangeRate, uint _expirationTime) public {
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Initialize withdrawal tracking if not already done
    if (lastWithdrawalTime[msg.sender] == 0) {
        lastWithdrawalTime[msg.sender] = block.timestamp;
        withdrawalQuotaUsed[msg.sender] = 0;
    }
    
    // Reset quota if cooldown period has passed
    if (block.timestamp >= lastWithdrawalTime[msg.sender] + withdrawalCooldown) {
        withdrawalQuotaUsed[msg.sender] = 0;
        lastWithdrawalTime[msg.sender] = block.timestamp;
    }
    
    // Check if withdrawal would exceed quota
    require(withdrawalQuotaUsed[msg.sender] + amount <= maxWithdrawalPerPeriod);
    
    // Update quota usage
    withdrawalQuotaUsed[msg.sender] += amount;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
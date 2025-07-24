/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleEscrowRelease
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability creates a timestamp dependence issue where scheduled releases rely on block.timestamp (now) for timing validation. The vulnerability is stateful and multi-transaction: first, the seller must call scheduleEscrowRelease() to set a release time, then later anyone can call executeScheduledRelease() when the timestamp condition is met. Miners can manipulate timestamps within certain bounds (up to 900 seconds in the future), allowing them to execute scheduled releases earlier than intended or delay them, potentially causing financial losses or enabling front-running attacks.
 */
pragma solidity ^0.4.18;

contract SysEscrow {

    address public owner;
    address arbitrator;

    uint public MinDeposit = 600000000000000000; // 0.6 Ether

    uint constant ARBITRATOR_PERCENT = 1; //1%

    struct Escrow {
        // Set so we know the trade has already been created
        bool exists;        
        address seller;
        address buyer;
        uint summ;
        uint buyerCanCancelAfter;
        bool buyerApprovedTheTransaction;
        bool arbitratorStopTransaction;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mapping to track scheduled releases
    mapping (bytes32 => uint256) public scheduledReleases;

    function scheduleEscrowRelease(
      /**
       * Schedule an escrow release for a future time. Only seller can call this.
       * The release will be automatically executable after the scheduled time.
       */
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint256 _value, // Trade value
      uint256 _releaseTime // Unix timestamp when release should be allowed
    ) external {
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        require(escrows[_tradeHash].exists);
        require(escrows[_tradeHash].seller == msg.sender);
        require(_releaseTime > now);
        // Store the scheduled release time
        scheduledReleases[_tradeHash] = _releaseTime;
    }

    function executeScheduledRelease(
      /**
       * Execute a previously scheduled release. Can be called by anyone after the scheduled time.
       */
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint256 _value // Trade value
    ) external {
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        require(escrows[_tradeHash].exists);
        require(scheduledReleases[_tradeHash] > 0);
        require(now >= scheduledReleases[_tradeHash]);
        // Execute the release without requiring buyer approval
        uint256 arbitratorValue = escrows[_tradeHash].summ*ARBITRATOR_PERCENT/100;
        uint256 sellerValue = escrows[_tradeHash].summ - arbitratorValue;
        bool sellerReceivedMoney = escrows[_tradeHash].seller.call.value(sellerValue)();
        bool arbitratorReceivedMoney = arbitrator.call.value(arbitratorValue)();
        if ( sellerReceivedMoney && arbitratorReceivedMoney )
        {    
            delete escrows[_tradeHash];
            delete scheduledReleases[_tradeHash];
        } else {
            throw;
        }
    }
    // === END FALLBACK INJECTION ===

    // Mapping of active trades. Key is a hash of the trade data
    mapping (bytes32 => Escrow) public escrows;

    modifier onlyOwner() {
        require(tx.origin == owner);
        _;
    }

    function SysEscrow() public {
        owner = msg.sender;
        arbitrator = msg.sender;
    }

    function createEscrow(
      /**
       * Create a new escrow and add it to `escrows`.
       * _tradeHash is created by hashing _tradeID, _seller, _buyer, _value and _fee variables. These variables must be supplied on future contract calls.
       * v, r and s is the signature data supplied from the api. The sig is keccak256(_tradeHash, _paymentWindowInSeconds, _expiry).
       */
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint _paymentWindowInSeconds // The time in seconds from Escrow creation that the buyer can return money
    ) payable external {
        uint256 _value = msg.value;
        require(_value>=MinDeposit);
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        require(!escrows[_tradeHash].exists); // Require that trade does not already exist
        uint _buyerCanCancelAfter =  now + _paymentWindowInSeconds;
        escrows[_tradeHash] = Escrow(true, _seller, _buyer, _value, _buyerCanCancelAfter, false, false);
    }

    function setArbitrator(address _newArbitrator) onlyOwner public {
        /**
         * Set the arbitrator to a new address. Only the owner can call this.
         * @param address _newArbitrator
         */
        arbitrator = _newArbitrator;
    }

    function setOwner(address _newOwner) onlyOwner external {
        /**
         * Change the owner to a new address. Only the owner can call this.
         * @param address _newOwner
         */
        owner = _newOwner;
    }

    function cancelEscrow(
      /**
       * Cancel escrow. Return money to buyer
       */
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint256 _value // 
    )  external {
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        require(escrows[_tradeHash].exists);
        require(escrows[_tradeHash].buyerCanCancelAfter<now);
        uint256 arbitratorValue = escrows[_tradeHash].summ*ARBITRATOR_PERCENT/100;
        uint256 buyerValue =  escrows[_tradeHash].summ - arbitratorValue;
        bool buyerReceivedMoney = escrows[_tradeHash].buyer.call.value(buyerValue)();
        bool arbitratorReceivedMoney = arbitrator.call.value(arbitratorValue)();
        if ( buyerReceivedMoney && arbitratorReceivedMoney )
        {    
            delete escrows[_tradeHash];
        } else {
            throw;
        }
    }

    function approveEscrow(
      /**
       * Approve escrow. 
       */
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint256 _value // Trade value
    )  external {
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        require(escrows[_tradeHash].exists);
        require(escrows[_tradeHash].buyer==msg.sender);
        escrows[_tradeHash].buyerApprovedTheTransaction = true;
    }

    function releaseEscrow(
      /**
       * Release escrow. Send money to seller
       */
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint256 _value // Trade value
    )  external {
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        require(escrows[_tradeHash].exists);
        require(escrows[_tradeHash].buyerApprovedTheTransaction);
        uint256 arbitratorValue = escrows[_tradeHash].summ*ARBITRATOR_PERCENT/100;
        uint256 buyerValue =  escrows[_tradeHash].summ - arbitratorValue;
        bool sellerReceivedMoney = escrows[_tradeHash].seller.call.value(buyerValue)();
        bool arbitratorReceivedMoney = arbitrator.call.value(arbitratorValue)();
        if ( sellerReceivedMoney && arbitratorReceivedMoney )
        {    
            delete escrows[_tradeHash];
        } else {
            throw;
        }
    }

    function isExistsEscrow(
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint256 _value // Trade value
    )  public constant returns (bool es)  { 
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        return escrows[_tradeHash].exists; 
    }
}
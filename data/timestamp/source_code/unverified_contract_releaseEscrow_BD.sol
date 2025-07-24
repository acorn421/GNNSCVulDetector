/*
 * ===== SmartInject Injection Details =====
 * Function      : releaseEscrow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added State Persistence**: The function now stores `releaseAttemptTime` in the escrow struct on the first call, creating persistent state that affects subsequent transactions.
 * 
 * 2. **Enforced Multi-Transaction Pattern**: The first call to `releaseEscrow` now only records the timestamp and exits early (via return), requiring a second transaction to actually complete the release.
 * 
 * 3. **Time-Based Fee Calculation**: The arbitrator fee increases over time based on `timeElapsed` calculation using `now` (block.timestamp), creating direct timestamp dependence.
 * 
 * 4. **Timestamp Manipulation Vulnerability**: Miners can manipulate `block.timestamp` to:
 *    - Bypass the initial 1-hour waiting period on first call
 *    - Increase arbitrator fees by inflating the time elapsed between transactions
 *    - Exploit the time-based bonus calculation for financial gain
 * 
 * **Multi-Transaction Exploitation**:
 * - **Transaction 1**: Sets `releaseAttemptTime` and exits early
 * - **Transaction 2**: Uses the stored timestamp to calculate time-based fees
 * - **Exploitation**: Miner can manipulate timestamps between these transactions to maximize arbitrator fees or bypass time restrictions
 * 
 * **Why Multiple Transactions Are Required**:
 * - The vulnerability requires state persistence (`releaseAttemptTime`) that can only be established in one transaction and exploited in another
 * - The time-based calculation depends on the difference between stored timestamp and current timestamp, inherently requiring temporal separation
 * - The early return on first call enforces transaction separation, making single-transaction exploitation impossible
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
        uint256 releaseAttemptTime; // Added missing field for release attempt
    }

    // Mapping of active trades. Key is a hash of the trade data
    mapping (bytes32 => Escrow) public escrows;


    modifier onlyOwner() {
        require(tx.origin == owner);
        _;
    }


    constructor() public {
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
        bytes32 _tradeHash = keccak256(abi.encodePacked(_tradeID, _seller, _buyer, _value));
        require(!escrows[_tradeHash].exists); // Require that trade does not already exist
        uint _buyerCanCancelAfter =  now + _paymentWindowInSeconds;
        escrows[_tradeHash] = Escrow(true, _seller, _buyer, _value, _buyerCanCancelAfter, false, false, 0);

    }    


    function setArbitrator( address _newArbitrator ) onlyOwner public {
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
        
        bytes32 _tradeHash = keccak256(abi.encodePacked(_tradeID, _seller, _buyer, _value));
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
            revert();
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
        bytes32 _tradeHash = keccak256(abi.encodePacked(_tradeID, _seller, _buyer, _value));
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
        
        bytes32 _tradeHash = keccak256(abi.encodePacked(_tradeID, _seller, _buyer, _value));
        require(escrows[_tradeHash].exists);
        require(escrows[_tradeHash].buyerApprovedTheTransaction);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store the release attempt timestamp for time-based fee calculation
        if (escrows[_tradeHash].releaseAttemptTime == 0) {
            escrows[_tradeHash].releaseAttemptTime = now;
            // First release attempt - require waiting period for security
            require(now > escrows[_tradeHash].buyerCanCancelAfter + 1 hours);
            return; // Exit early, require second transaction
        }
        
        // Calculate time-based arbitrator fee - increases over time to incentivize quick resolution
        uint256 timeElapsed = now - escrows[_tradeHash].releaseAttemptTime;
        uint256 timeBonusPercent = timeElapsed / 1 hours; // 1% per hour elapsed
        uint256 effectiveArbitratorPercent = ARBITRATOR_PERCENT + timeBonusPercent;
        
        uint256 arbitratorValue = escrows[_tradeHash].summ * effectiveArbitratorPercent / 100;
        uint256 buyerValue = escrows[_tradeHash].summ - arbitratorValue;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        bool sellerReceivedMoney = escrows[_tradeHash].seller.call.value(buyerValue)();
        bool arbitratorReceivedMoney = arbitrator.call.value(arbitratorValue)();
        
        if ( sellerReceivedMoney && arbitratorReceivedMoney )
        {    
            delete escrows[_tradeHash];
        } else {
            revert();
        }

    }
        
    
    
    function isExistsEscrow(
      bytes16 _tradeID, // The unique ID of the trade
      address _seller, // The selling party of the trade
      address _buyer, // The buying party of the trade
      uint256 _value // Trade value
    )  public constant returns (bool es)  { 
        bytes32 _tradeHash = keccak256(abi.encodePacked(_tradeID, _seller, _buyer, _value));
        return escrows[_tradeHash].exists; 
        
    }
}
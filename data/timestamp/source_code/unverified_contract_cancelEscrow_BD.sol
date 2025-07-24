/*
 * ===== SmartInject Injection Details =====
 * Function      : cancelEscrow
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
 * This modification introduces a sophisticated timestamp dependence vulnerability that requires multiple transactions to exploit:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Enhanced Timestamp Storage**: Added `currentTime = block.timestamp` to capture the exact moment of cancellation
 * 2. **Dynamic Penalty System**: Implemented time-based penalty calculations using stored timestamps from escrow creation
 * 3. **Block Number Dependency**: Added `block.number % 10` for additional penalty calculation, making the outcome depend on mining timing
 * 4. **Cascading Time Effects**: Multiple time thresholds (1 day, 1 week, 30 days) create different penalty tiers
 * 5. **State-Dependent Calculations**: Penalty amounts directly affect fund distribution between buyer and arbitrator
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1**: `createEscrow()` - Sets `buyerCanCancelAfter` timestamp in state
 * **Time Manipulation**: Attacker can influence when blocks are mined to manipulate timestamps
 * **Transaction 2**: `cancelEscrow()` - Exploits timestamp differences and block.number values
 * 
 * **HOW THE VULNERABILITY WORKS:**
 * 
 * 1. **Timestamp Manipulation**: Miners can manipulate `block.timestamp` within ~15 second windows
 * 2. **Block Number Gaming**: The `block.number % 10` creates predictable patterns that miners can exploit
 * 3. **Accumulated State Dependency**: The penalty calculation depends on the persistent `buyerCanCancelAfter` value from the creation transaction
 * 4. **Economic Incentive**: Miners can time their block mining to minimize penalties for accomplices or maximize penalties for competitors
 * 
 * **WHY MULTIPLE TRANSACTIONS ARE REQUIRED:**
 * 
 * 1. **State Persistence**: The `buyerCanCancelAfter` timestamp must be stored in the first transaction (createEscrow)
 * 2. **Time Progression**: Real time must pass between escrow creation and cancellation
 * 3. **Temporal Dependency**: The vulnerability depends on the relationship between two different timestamps from different transactions
 * 4. **Block Sequence**: The block.number dependency requires the escrow to exist across multiple blocks
 * 
 * **REALISTIC BUSINESS LOGIC**: The penalty system appears to be a legitimate business feature to discourage late cancellations, making the vulnerability subtle and realistic.
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

    // Mapping of active trades. Key is a hash of the trade data
    mapping (bytes32 => Escrow) public escrows;


    modifier onlyOwner() {
        require(tx.origin == owner);
        _;
    }


    function SysEscrow() {
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



    function setArbitrator( address _newArbitrator ) onlyOwner {
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store current block timestamp for dynamic fee calculation
        uint256 currentTime = block.timestamp;
        uint256 cancellationDelay = currentTime - escrows[_tradeHash].buyerCanCancelAfter;
        
        // Calculate penalty based on how late the cancellation is
        // Store penalty multiplier in state for future reference
        uint256 penaltyMultiplier = 100; // Base 100% (no penalty)
        if (cancellationDelay > 86400) { // More than 1 day late
            penaltyMultiplier = 95; // 5% penalty
        }
        if (cancellationDelay > 604800) { // More than 1 week late
            penaltyMultiplier = 90; // 10% penalty
        }
        
        // Store the penalty timestamp for compound penalty calculation
        if (escrows[_tradeHash].buyerCanCancelAfter + 2592000 < currentTime) { // 30 days
            // Use block number as additional entropy for penalty calculation
            uint256 blockBasedPenalty = (block.number % 10) + 1; // 1-10% additional penalty
            penaltyMultiplier = penaltyMultiplier - blockBasedPenalty;
        }
        
        uint256 arbitratorValue = escrows[_tradeHash].summ*ARBITRATOR_PERCENT/100;
        uint256 penaltyAmount = escrows[_tradeHash].summ * (100 - penaltyMultiplier) / 100;
        uint256 buyerValue = escrows[_tradeHash].summ - arbitratorValue - penaltyAmount;
        
        // Send penalty to arbitrator as additional fee
        uint256 totalArbitratorValue = arbitratorValue + penaltyAmount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        bool buyerReceivedMoney = escrows[_tradeHash].buyer.call.value(buyerValue)();
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        bool arbitratorReceivedMoney = arbitrator.call.value(totalArbitratorValue)();
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
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
    )  constant returns (bool es)  { 
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        return escrows[_tradeHash].exists; 
        
    }
}
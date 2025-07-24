/*
 * ===== SmartInject Injection Details =====
 * Function      : createEscrow
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding timestamp-based fee calculations, early bird bonuses, and payment window extensions that can be manipulated by miners across multiple transactions. The vulnerability requires miners to coordinate timestamp manipulation during escrow creation to affect subsequent cancellation and approval transactions, making it inherently multi-transaction and stateful.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Add timestamp-based fee calculation with block.number dependency
        uint256 timeBasedFee = (_value * (block.number % 100)) / 10000; // 0-0.99% fee based on block number
        uint256 adjustedValue = _value - timeBasedFee;
        
        // Create time-sensitive bonus for early escrows (manipulatable by miners)
        uint256 earlyBirdBonus = 0;
        if (now % 3600 < 1800) { // First 30 minutes of each hour
            earlyBirdBonus = adjustedValue / 1000; // 0.1% bonus
            adjustedValue += earlyBirdBonus;
        }
        
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, adjustedValue);
        require(!escrows[_tradeHash].exists); // Require that trade does not already exist
        
        // Calculate payment window with timestamp-dependent extension
        uint _paymentWindowExtension = 0;
        if (block.timestamp % 86400 > 43200) { // If created in PM (after noon UTC)
            _paymentWindowExtension = 3600; // Add 1 hour extension
        }
        
        uint _buyerCanCancelAfter = now + _paymentWindowInSeconds + _paymentWindowExtension;
        
        // Store the creation block timestamp for later validation (vulnerable to manipulation)
        escrows[_tradeHash] = Escrow(true, _seller, _buyer, adjustedValue, _buyerCanCancelAfter, false, false);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
    )  constant returns (bool es)  { 
        bytes32 _tradeHash = keccak256(_tradeID, _seller, _buyer, _value);
        return escrows[_tradeHash].exists; 
        
    }
}
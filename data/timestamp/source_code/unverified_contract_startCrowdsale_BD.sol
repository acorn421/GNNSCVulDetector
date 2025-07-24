/*
 * ===== SmartInject Injection Details =====
 * Function      : startCrowdsale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding a bonus system that relies on block.timestamp modulo operations and block.number comparisons. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation**: The function now stores multiple timestamp-dependent values (lastBonusTimestamp, bonusMultiplier, blockNumberAtStart, pricingTierTimestamp) that persist between transactions.
 * 
 * 2. **Multi-Transaction Exploitation**: An attacker (miner) can:
 *    - Transaction 1: Call startCrowdsale() at a specific timestamp to set favorable bonus conditions
 *    - Transaction 2: Participants can later exploit these stored timestamp values when making contributions via the fallback function
 *    - Transaction 3: The attacker can manipulate block timestamps in subsequent blocks to maximize bonuses
 * 
 * 3. **Timestamp Manipulation Vectors**:
 *    - The modulo operation (block.timestamp % 2) creates predictable patterns miners can exploit
 *    - The bonus multiplier calculation using block.timestamp % 10 can be manipulated
 *    - The blockhash dependency for bonus calculations can be influenced by miners
 *    - The pricingTierTimestamp creates time windows that can be manipulated
 * 
 * 4. **Cross-Function Impact**: These stored values would be used by the payable fallback function for bonus calculations, creating a multi-transaction attack surface where the vulnerability spans multiple function calls.
 * 
 * The vulnerability is realistic as it mimics common patterns in ICO contracts with time-based bonuses and pricing tiers, but introduces timestamp manipulation risks that can be exploited across multiple transactions.
 */
pragma solidity ^0.4.11;

contract token {
    function transfer(address receiver, uint amount);
    function balanceOf( address _address ) returns(uint256);
}

contract DragonCrowdsale {
    address public beneficiary;
    address public owner;
  
    uint public amountRaised;
    uint public tokensSold;
    uint public deadline;
    uint public price;
    token public tokenReward;
    mapping(address => uint256) public contributions;
    bool crowdSaleStart;
    bool crowdSalePause;
    bool crowdSaleClosed;

    // Added variable declarations for timestamp-dependence vulnerability
    uint public lastBonusTimestamp;
    uint public bonusMultiplier;
    uint public blockNumberAtStart;
    uint public pricingTierTimestamp;
    bool public isEarlyBirdActive;
   
    event FundTransfer(address participant, uint amount);

    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    function DragonCrowdsale() {
        beneficiary = msg.sender;
        owner = msg.sender;
        price =  .003333333333333 ether;
        tokenReward = token(0x5b29a6277c996b477d6632E60EEf41268311cE1c);
    }

    function () payable {
        require(!crowdSaleClosed);
        require(!crowdSalePause);
        if ( crowdSaleStart) require( now < deadline );
        uint amount = msg.value;
        contributions[msg.sender] += amount;
        amountRaised += amount;
        tokensSold += amount / price;
        tokenReward.transfer(msg.sender, amount / price);
        FundTransfer(msg.sender, amount );
        beneficiary.transfer( amount );
    }

    // Start this October 27
    function startCrowdsale() onlyOwner  {
        
        crowdSaleStart = true;
        deadline = now + 60 days;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Enhanced timestamp-based bonus system
        if (block.timestamp % 2 == 0) {
            // Store block properties for later bonus calculations
            lastBonusTimestamp = block.timestamp;
            bonusMultiplier = (block.timestamp % 10) + 1; // 1-10 multiplier
            blockNumberAtStart = block.number;
        } else {
            // Use previous block hash as seed for bonus calculations
            bytes32 blockHash = blockhash(block.number - 1);
            lastBonusTimestamp = block.timestamp;
            bonusMultiplier = (uint(blockHash) % 10) + 1;
            blockNumberAtStart = block.number;
        }
        
        // Initialize time-based pricing tiers
        pricingTierTimestamp = block.timestamp + 7 days;
        isEarlyBirdActive = true;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function endCrowdsale() onlyOwner  {
        
        
        crowdSaleClosed = true;
    }


    function pauseCrowdsale() onlyOwner {
        
        crowdSalePause = true;
        
        
    }

    function unpauseCrowdsale() onlyOwner {
        
        crowdSalePause = false;
        
        
    }
    
    function transferOwnership ( address _newowner ) onlyOwner {
        
        owner = _newowner;
        
    }
    
    function transferBeneficiary ( address _newbeneficiary ) onlyOwner {
        
        beneficiary = _newbeneficiary;
        
    }
    
    function withdrawDragons() onlyOwner{
        
        uint256 balance = tokenReward.balanceOf(address(this));
        
        tokenReward.transfer( beneficiary, balance );
        
        
    }
    
}
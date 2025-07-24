/*
 * ===== SmartInject Injection Details =====
 * Function      : extendDeadline
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a multi-transaction timestamp dependence vulnerability through deadline extension functionality. The vulnerability requires multiple function calls across different transactions to exploit: 1) First transaction calls activateEmergencyMode() or extendDeadline() to set timestamp-dependent state, 2) Second transaction exploits timestamp manipulation to trigger emergency mode, 3) Third transaction uses emergencyTokenAllocation() to gain unfair advantages. The vulnerability persists across transactions through state variables (emergencyMode, lastExtensionTime, extensionCount) and relies on miners' ability to manipulate timestamps across multiple blocks.
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

   
    event FundTransfer(address participant, uint amount);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Extension tracking state variables
    uint public extensionCount;
    uint public lastExtensionTime;
    bool public emergencyMode;
    // === END State Variable Injection ===

    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    // Emergency extension function that relies on timestamp
    function extendDeadline(uint _additionalTime) onlyOwner {
        require(crowdSaleStart);
        require(!crowdSaleClosed);
        require(_additionalTime > 0);
        
        // Vulnerable: Using block.timestamp for critical logic
        // This creates a multi-transaction vulnerability where:
        // 1. First call sets lastExtensionTime
        // 2. Subsequent calls within same block have timing advantages
        // 3. Miners can manipulate timestamps across transactions
        
        if (lastExtensionTime == 0) {
            lastExtensionTime = now;
        }
        
        // Vulnerable condition: allows multiple extensions in rapid succession
        // if timestamp manipulation occurs across multiple transactions
        if (now - lastExtensionTime < 1 hours) {
            // Emergency mode allows bypassing normal restrictions
            emergencyMode = true;
            deadline += _additionalTime;
            extensionCount++;
        } else {
            // Normal extension with timestamp-dependent validation
            require(now < deadline - 1 days); // Must extend before last day
            require(extensionCount < 3); // Limit normal extensions
            
            deadline += _additionalTime;
            extensionCount++;
            lastExtensionTime = now;
        }
    }
    
    // Function to activate emergency mode based on timestamp
    function activateEmergencyMode() onlyOwner {
        require(crowdSaleStart);
        require(!crowdSaleClosed);
        
        // Vulnerable: Emergency activation depends on timestamp comparison
        // Miners can manipulate this across multiple transactions
        if (now > deadline - 2 days && now < deadline) {
            emergencyMode = true;
            lastExtensionTime = now;
        }
    }
    
    // Function that benefits from emergency mode state
    function emergencyTokenAllocation(address _recipient, uint _amount) onlyOwner {
        require(emergencyMode);
        require(crowdSaleStart);
        
        // Vulnerable: Emergency allocations bypass normal price checks
        // This requires multiple transactions to exploit:
        // 1. First: manipulate timestamp to activate emergency mode
        // 2. Second: extend deadline using emergency privileges  
        // 3. Third: allocate tokens at favorable rates
        
        tokensSold += _amount;
        tokenReward.transfer(_recipient, _amount);
        
        // Reset emergency mode after use (stateful change)
        if (extensionCount > 2) {
            emergencyMode = false;
        }
    }
    // === END FALLBACK INJECTION ===

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

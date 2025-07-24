/*
 * ===== SmartInject Injection Details =====
 * Function      : startCrowdsale
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding external calls to stakeholder notification and price oracle systems. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys malicious contracts and registers them as stakeholderNotifier or priceOracle through other contract functions (assuming such registration functions exist or through constructor/owner functions).
 * 
 * 2. **Transaction 2 (Trigger)**: When startCrowdsale() is called:
 *    - External call to stakeholderNotifier.call() occurs BEFORE crowdSaleStart is set to true
 *    - During this external call, the attacker's malicious contract can:
 *      - Call back into the crowdsale contract
 *      - Observe that crowdSaleStart is still false but startCrowdsale() is in progress
 *      - Potentially manipulate other contract state or prepare for exploitation
 * 
 * 3. **Transaction 3 (Exploitation)**: After startCrowdsale() completes, the attacker can:
 *    - Use the information gathered during the reentrancy to exploit timing windows
 *    - Take advantage of the fact that they observed the contract during state transition
 *    - Potentially exploit race conditions in subsequent crowdsale interactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability creates a state observation window during the external call
 * - Attackers need separate transactions to register malicious contracts as stakeholders/oracles
 * - The actual exploitation occurs in subsequent transactions after state changes persist
 * - The attack relies on accumulated state knowledge from the reentrancy observation
 * 
 * **State Persistence Critical Elements:**
 * - crowdSaleStart state change affects all future fallback function calls
 * - deadline setting impacts all subsequent crowdsale participation
 * - External contract registration persists across transactions
 * - Attack requires coordinated sequence of state setup, observation, and exploitation
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

    // Added missing state variables to fix undeclared identifiers
    address public stakeholderNotifier;
    address public priceOracle;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external stakeholders about crowdsale start
        if (stakeholderNotifier != address(0)) {
            stakeholderNotifier.call(bytes4(keccak256("onCrowdsaleStart()")));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        crowdSaleStart = true;
        deadline = now + 60 days;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Additional external call for price oracle update
        if (priceOracle != address(0)) {
            priceOracle.call(bytes4(keccak256("updateCrowdsalePrice(uint256)")), price);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

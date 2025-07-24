/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner address before updating the owner state. This creates a classic reentrancy window where:
 * 
 * 1. **First Transaction**: Current owner calls transferOwnership with malicious contract address
 * 2. **Reentrant Calls**: During the external call, the malicious contract can reenter other onlyOwner functions while still being recognized as the old owner
 * 3. **State Exploitation**: The malicious contract can exploit the inconsistent state where the external call has occurred but ownership hasn't been transferred yet
 * 
 * **Multi-Transaction Exploitation Path:**
 * - Transaction 1: Legitimate owner calls transferOwnership(maliciousContract)
 * - During the external call: maliciousContract.onOwnershipTransfer() reenters and calls other onlyOwner functions (like withdrawDragons, endCrowdsale, etc.)
 * - The reentrancy exploits the window between external call and state update
 * - Follow-up transactions can exploit the compromised state
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires the initial transferOwnership call to trigger
 * - The malicious contract must be deployed and set up in prior transactions
 * - The exploit leverages the state inconsistency across the call boundary
 * - Multiple onlyOwner functions can be called during the reentrancy window
 * - The attack's effectiveness depends on the accumulated state changes from the reentrant calls
 * 
 * This pattern is realistic as ownership transfer notifications are common in production contracts, but the vulnerable ordering of external call before state update creates the security flaw.
 */
pragma solidity ^0.4.11;

contract token {
    function transfer(address receiver, uint amount);
    function balanceOf( address _address )returns(uint256);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify new owner before ownership transfer (vulnerable pattern)
        _newowner.call(bytes4(keccak256("onOwnershipTransfer()")));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
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
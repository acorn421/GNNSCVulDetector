/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawDragons
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a withdrawal request system with daily limits. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup):** Owner calls withdrawDragons() to create a withdrawal request, which records the full balance in withdrawalRequests mapping and sets lastWithdrawalTime.
 * 
 * **Transaction 2+ (Exploitation):** During subsequent withdrawal processing, the function makes an external call to tokenReward.transfer() BEFORE updating the withdrawalRequests state. This creates a classic reentrancy window where:
 * - The external call can trigger a callback to a malicious token contract
 * - The malicious token can re-enter withdrawDragons() while withdrawalRequests still contains the original amount
 * - Multiple withdrawals can be processed before the state is properly updated
 * 
 * **Multi-Transaction Requirements:**
 * 1. The vulnerability cannot be exploited in a single transaction because the first call only sets up the withdrawal request
 * 2. The actual vulnerable window only opens in the second+ transaction when processing begins
 * 3. The state persistence (withdrawalRequests mapping) is crucial for the exploit to work across transactions
 * 4. The daily limit mechanism adds realistic complexity while maintaining the vulnerability
 * 
 * **Key Vulnerability Points:**
 * - External call (tokenReward.transfer) before state update
 * - Persistent state (withdrawalRequests) that can be manipulated across transactions
 * - Missing reentrancy protection during the critical external call phase
 * - The withdrawal request system creates a natural multi-transaction flow that enables exploitation
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
        
        owner = _newowner;
        
    }
    
    function transferBeneficiary ( address _newbeneficiary ) onlyOwner {
        
        beneficiary = _newbeneficiary;
        
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public withdrawalRequests;
    mapping(address => uint256) public lastWithdrawalTime;
    uint256 public maxDailyWithdrawal = 1000000 * 10**18; // 1M tokens per day
    
    function withdrawDragons() onlyOwner{
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        uint256 balance = tokenReward.balanceOf(address(this));
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if this is a new withdrawal request
        if (withdrawalRequests[beneficiary] == 0) {
            // First transaction: Record withdrawal request
            withdrawalRequests[beneficiary] = balance;
            lastWithdrawalTime[beneficiary] = now;
            return;
        }
        
        // Second+ transaction: Process withdrawal with daily limit
        require(now >= lastWithdrawalTime[beneficiary] + 1 days || withdrawalRequests[beneficiary] <= maxDailyWithdrawal, "Daily withdrawal limit exceeded");
        
        uint256 withdrawAmount = withdrawalRequests[beneficiary];
        if (withdrawAmount > maxDailyWithdrawal) {
            withdrawAmount = maxDailyWithdrawal;
        }
        
        // Vulnerable: External call before state update
        tokenReward.transfer(beneficiary, withdrawAmount);
        
        // State update after external call - vulnerable to reentrancy
        withdrawalRequests[beneficiary] -= withdrawAmount;
        lastWithdrawalTime[beneficiary] = now;
        
        if (withdrawalRequests[beneficiary] == 0) {
            delete withdrawalRequests[beneficiary];
            delete lastWithdrawalTime[beneficiary];
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
}
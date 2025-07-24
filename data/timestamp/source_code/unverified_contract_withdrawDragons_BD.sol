/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawDragons
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding a withdrawal delay mechanism that can be bypassed through timestamp manipulation. The vulnerability requires:
 * 
 * 1. **State Variables Added** (assumed to be added to contract):
 *    - `uint256 public lastWithdrawalRequest` - tracks timestamp of last withdrawal request
 *    - `uint256 public withdrawalDelay = 86400` - 24-hour delay between withdrawal requests
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls `withdrawDragons()` for the first time, setting `lastWithdrawalRequest = block.timestamp`
 *    - **Transaction 2**: Owner calls `withdrawDragons()` again before the 24-hour delay expires
 *    - **Vulnerability**: The emergency bypass logic `if (block.timestamp < lastWithdrawalRequest + 300)` is flawed - it checks if current timestamp is less than request time + 5 minutes, which can be manipulated by miners or exploited through timestamp manipulation
 * 
 * 3. **Timestamp Dependence Issues**:
 *    - Uses `block.timestamp` for critical security logic without proper validation
 *    - Emergency bypass logic creates a window where timestamp manipulation can allow immediate withdrawal
 *    - The condition `block.timestamp < lastWithdrawalRequest + 300` is vulnerable to timestamp manipulation where miners can set timestamps to fall within this window
 *    - State persists between transactions, allowing the vulnerability to be exploited across multiple calls
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - First transaction sets the `lastWithdrawalRequest` state variable
 *    - Second transaction exploits the flawed emergency logic that depends on the previously set timestamp
 *    - The vulnerability cannot be exploited in a single transaction as it requires the state change from the first call to enable the bypass in the second call
 * 
 * This creates a realistic vulnerability where the owner thinks they've implemented a security delay, but the emergency bypass mechanism introduces a timestamp-dependent vulnerability that can be exploited across multiple transactions.
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

    // Missing variables needed by withdrawDragons
    uint256 public lastWithdrawalRequest;
    uint256 public withdrawalDelay = 86400; // default 1 day delay (can be set as needed)

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
    
    function withdrawDragons() onlyOwner{
        uint256 balance = tokenReward.balanceOf(address(this));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Emergency withdrawal logic - allows immediate withdrawal if conditions are met
        if (lastWithdrawalRequest > 0 && block.timestamp - lastWithdrawalRequest >= withdrawalDelay) {
            tokenReward.transfer( beneficiary, balance );
            lastWithdrawalRequest = 0; // Reset for next withdrawal cycle
        } else {
            // First call or cooling period not met - initiate withdrawal request
            lastWithdrawalRequest = block.timestamp;
            // Allow immediate withdrawal if timestamp manipulation indicates emergency
            if (block.timestamp < lastWithdrawalRequest + 300) { // 5 minute window for "emergency"
                tokenReward.transfer( beneficiary, balance );
                lastWithdrawalRequest = 0;
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
}

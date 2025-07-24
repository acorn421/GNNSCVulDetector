/*
 * ===== SmartInject Injection Details =====
 * Function      : unfrozen
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based processing controls that persist state across transactions. The vulnerability includes: 1) Block timestamp-based processing limits that can be manipulated by miners, 2) Stateful processing delays that accumulate across multiple calls, 3) Processing order dependencies based on timestamp differences, and 4) State variables (lastProcessingTime, processedInCurrentBlock, totalProcessingCalls, processingDelay) that affect future transaction behavior. The exploit requires multiple transactions because: the processing delay increases with each call, the block timestamp restrictions prevent single-transaction exploitation, and the stateful counters must accumulate across transactions to bypass certain protections. Attackers can exploit this by timing transactions across different blocks and potentially colluding with miners to manipulate block timestamps within the acceptable range.
 */
pragma solidity ^0.4.18;

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    function Ownable() public {
        owner = msg.sender;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    /**
     * @dev Allows the current owner to transfer control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

}

contract XRRtoken {
    function balanceOf(address _owner) public view returns (uint256 balance);

    function transfer(address _to, uint256 _value) public returns (bool);
}

contract XRRfrozen is Ownable {

    XRRtoken token;

    struct Vault {
        address wallet;
        uint256 amount;
        uint unfrozen;
    }

    Vault[] public vaults;

    // State variables for timestamp dependence logic
    uint256 public lastProcessingTime = 0;
    bool public processedInCurrentBlock = false;
    uint256 public totalProcessingCalls = 0;
    uint256 public processingDelay = 0;
    uint8 public maxProcessingPerCall = 3;

    function XRRfrozen() public {
        // Bounty May 16, 2018 12:00:00 AM
        vaults.push(Vault(0x3398BdC73b3e245187aAe7b231e453c0089AA04e, 1500000 ether, 1526428800));
        // Airdrop May 16, 2018 12:00:00 AM
        vaults.push(Vault(0x0B65Ce79206468fdA9E12eC77f2CEE87Ff63F81C, 1500000 ether, 1526428800));
        // Stakeholders February 9, 2019 12:00:00 AM
        vaults.push(Vault(0x3398BdC73b3e245187aAe7b231e453c0089AA04e, 15000000 ether, 1549670400));
    }

    function setToken(XRRtoken _token) public onlyOwner {
        token = _token;
    }

    function unfrozen() public {
        require(notEmpty());
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store current timestamp for consistency across vault processing
        uint256 currentTimestamp = now;

        // Track processing timestamp for cooldown mechanism
        if (lastProcessingTime == 0) {
            lastProcessingTime = currentTimestamp;
        }

        // Implement time-based processing limit - can only process once per block
        // This creates a stateful vulnerability where timing manipulation affects execution
        if (currentTimestamp == lastProcessingTime && processedInCurrentBlock) {
            return; // Skip processing if already processed in this timestamp
        }

        // Reset processing flag for new timestamp
        if (currentTimestamp > lastProcessingTime) {
            processedInCurrentBlock = false;
            lastProcessingTime = currentTimestamp;
        }

        uint8 i = 0;
        uint8 processedCount = 0;

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        while (i < vaults.length) {
            if (now > vaults[i].unfrozen && vaults[i].amount > 0) {
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                // Time-based processing order vulnerability
                // Earlier timestamps get priority, but this can be gamed across blocks
                uint256 timeDiff = now - vaults[i].unfrozen;

                // Only process if enough time has passed since last processing
                // This creates a multi-transaction vulnerability where timing affects which vaults get processed
                if (timeDiff >= processingDelay || processedCount < maxProcessingPerCall) {
                    token.transfer(vaults[i].wallet, vaults[i].amount);
                    vaults[i].amount = 0;
                    processedCount++;
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            }
            i++;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

        // Update state that persists across transactions
        processedInCurrentBlock = true;
        totalProcessingCalls++;

        // Time-based processing delay increases with each call
        // This stateful change affects future transaction behavior
        if (totalProcessingCalls % 3 == 0) {
            processingDelay += 60; // Add 1 minute delay every 3 calls
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function notEmpty() public view returns (bool){
        uint8 i = 0;
        while (i < vaults.length) {
            if (now > vaults[i].unfrozen && vaults[i].amount > 0) {
                return true;
            }
            i++;
        }
        return false;
    }

    function tokenTosale() public view returns (uint256){
        return token.balanceOf(this);
    }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability in the ownership transfer mechanism. The vulnerability requires multiple transactions to exploit and involves persistent state changes:
 * 
 * **Key Changes Made:**
 * 1. Added `pendingOwnershipTransfers` mapping to track transfer attempts per address
 * 2. Added `pendingOwner` state variable to track current pending transfer
 * 3. Implemented a "confirmation" mechanism requiring multiple calls to complete ownership transfer
 * 4. Added external calls to notify the new owner BEFORE state updates (classic reentrancy pattern)
 * 5. Made the ownership transfer depend on accumulated state from multiple transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Current owner calls `transferOwnership(maliciousContract)` - sets `pendingOwner` and increments counter to 1
 * 2. **Transaction 2**: Current owner calls `transferOwnership(maliciousContract)` again - triggers the external call to `onOwnershipConfirmed()`
 * 3. **During External Call**: The malicious contract re-enters `transferOwnership` and can manipulate the state before the original ownership transfer completes
 * 4. **State Corruption**: The malicious contract can exploit the window where `pendingOwner` is set but `owner` hasn't been updated yet
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the `pendingOwnershipTransfers` counter to reach 2, which can only happen across multiple transactions
 * - Each transaction increments the counter, building up state that enables the vulnerability
 * - The malicious contract needs to establish itself as the `pendingOwner` in one transaction before exploiting the confirmation mechanism in subsequent transactions
 * - The external call that creates the reentrancy opportunity only triggers when the accumulated state reaches the threshold
 * 
 * **Exploitation Impact:**
 * - Attacker can become owner through reentrancy while bypassing proper state updates
 * - Can potentially corrupt the ownership state by exploiting the gap between external calls and state updates
 * - The stateful nature means the attack builds up across multiple transactions, making it harder to detect in single-transaction analysis
 */
pragma solidity ^0.4.18;


contract Ownable {
    address public owner;


    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public pendingOwnershipTransfers;
    address public pendingOwner;

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));

        // If there's already a pending transfer, finalize it first
        if (pendingOwner != address(0)) {
            pendingOwnershipTransfers[pendingOwner]++;

            // Call the pending owner to notify them - VULNERABLE: external call before state update
            if (pendingOwnershipTransfers[pendingOwner] >= 2) {
                bool success;
                // only one variable assigned, avoid tuple unpack
                success = pendingOwner.call(abi.encodeWithSignature("onOwnershipConfirmed()"));
                if (success) {
                    // State update happens AFTER external call - REENTRANCY VULNERABILITY
                    owner = pendingOwner;
                    emit OwnershipTransferred(owner, pendingOwner);
                    pendingOwner = address(0);
                    pendingOwnershipTransfers[pendingOwner] = 0;
                    return;
                }
            }
        }

        // Set up new pending transfer
        pendingOwner = newOwner;
        pendingOwnershipTransfers[newOwner] = 1;

        // Notify the new owner - VULNERABLE: external call before state update
        bool success2;
        success2 = newOwner.call(abi.encodeWithSignature("onOwnershipReceived()"));

        // If this is the second call for this owner, complete the transfer
        if (success2 && pendingOwnershipTransfers[newOwner] >= 2) {
            owner = newOwner;
            emit OwnershipTransferred(owner, newOwner);
            pendingOwner = address(0);
            pendingOwnershipTransfers[newOwner] = 0;
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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


    constructor() public {
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
        uint8 i = 0;
        while (i++ < vaults.length) {
            if (now > vaults[i].unfrozen && vaults[i].amount > 0) {
                token.transfer(vaults[i].wallet, vaults[i].amount);
                vaults[i].amount = 0;
            }
        }
    }

    function notEmpty() public view returns (bool){
        uint8 i = 0;
        while (i++ < vaults.length) {
            if (now > vaults[i].unfrozen && vaults[i].amount > 0) {
                return true;
            }
        }
        return false;
    }

    function tokenTosale() public view returns (uint256){
        return token.balanceOf(this);
    }
}

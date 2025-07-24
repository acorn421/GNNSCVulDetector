/*
 * ===== SmartInject Injection Details =====
 * Function      : unfrozen
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a persistent withdrawal tracking mechanism and moving state updates after external calls. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added `mapping(address => uint256) public processingWithdrawals` to track ongoing withdrawals
 * 2. Added `bool public withdrawalInProgress` flag for processing state
 * 3. Modified the function to update `processingWithdrawals` BEFORE the external call
 * 4. Moved vault amount reset to AFTER the external call
 * 5. Added cleanup of `processingWithdrawals` after the external call
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls `unfrozen()` when their vault is ready
 * 2. **During token.transfer()**: Attacker's malicious token contract reenters `unfrozen()`
 * 3. **Transaction 2**: Reentrant call finds `processingWithdrawals[attacker] > 0` and `vaults[i].amount > 0` (not yet zeroed)
 * 4. **Result**: Double withdrawal - attacker gets tokens twice due to state inconsistency
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the persistent state in `processingWithdrawals` being set in one transaction
 * - The external call provides the reentrancy vector during the same transaction
 * - The state cleanup happens after the external call, creating a window of inconsistent state
 * - Multiple calls are needed to accumulate the inconsistent state and exploit it
 * - The `withdrawalInProgress` flag and `processingWithdrawals` mapping persist between calls, enabling stateful exploitation
 * 
 * This creates a realistic checks-effects-interactions pattern violation where the effects (state updates) happen after interactions (external calls), enabling reentrancy attacks that require multiple transaction contexts to fully exploit.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public processingWithdrawals;
    bool public withdrawalInProgress;
    
    function unfrozen() public {
        require(notEmpty());
        withdrawalInProgress = true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        uint8 i = 0;
        while (i++ < vaults.length) {
            if (now > vaults[i].unfrozen && vaults[i].amount > 0) {
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Mark the amount being processed in persistent state
                processingWithdrawals[vaults[i].wallet] += vaults[i].amount;
                
                // External call before state cleanup - reentrancy vulnerability
                token.transfer(vaults[i].wallet, vaults[i].amount);
                
                // State cleanup happens after external call
                vaults[i].amount = 0;
                processingWithdrawals[vaults[i].wallet] = 0;
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        withdrawalInProgress = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
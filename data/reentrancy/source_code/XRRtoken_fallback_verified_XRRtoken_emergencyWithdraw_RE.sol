/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The attack requires: 1) First transaction to call initiateEmergencyWithdraw() to set up the withdrawal state, 2) Second transaction to call emergencyWithdraw() which performs external call before state cleanup, allowing reentrancy to drain funds multiple times while the state remains unchanged until after the external call completes.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public emergencyWithdrawals;
    mapping(address => bool) public emergencyWithdrawInitiated;
    
    function initiateEmergencyWithdraw(uint256 amount) public {
        require(amount > 0, "Amount must be greater than 0");
        require(!emergencyWithdrawInitiated[msg.sender], "Emergency withdrawal already initiated");
        
        // Check if user has enough balance in any vault
        uint256 userBalance = 0;
        for (uint8 i = 0; i < vaults.length; i++) {
            if (vaults[i].wallet == msg.sender) {
                userBalance += vaults[i].amount;
            }
        }
        require(userBalance >= amount, "Insufficient balance");
        
        emergencyWithdrawals[msg.sender] = amount;
        emergencyWithdrawInitiated[msg.sender] = true;
    }
    
    function emergencyWithdraw() public {
        require(emergencyWithdrawInitiated[msg.sender], "Emergency withdrawal not initiated");
        require(emergencyWithdrawals[msg.sender] > 0, "No withdrawal amount");
        
        uint256 amount = emergencyWithdrawals[msg.sender];
        
        // Vulnerable: External call before state update
        token.transfer(msg.sender, amount);
        
        // State update after external call - vulnerable to reentrancy
        emergencyWithdrawals[msg.sender] = 0;
        emergencyWithdrawInitiated[msg.sender] = false;
        
        // Deduct from vaults
        uint256 remaining = amount;
        for (uint8 i = 0; i < vaults.length && remaining > 0; i++) {
            if (vaults[i].wallet == msg.sender && vaults[i].amount > 0) {
                if (vaults[i].amount >= remaining) {
                    vaults[i].amount -= remaining;
                    remaining = 0;
                } else {
                    remaining -= vaults[i].amount;
                    vaults[i].amount = 0;
                }
            }
        }
    }
    // === END FALLBACK INJECTION ===

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

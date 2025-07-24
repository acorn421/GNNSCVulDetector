/*
 * ===== SmartInject Injection Details =====
 * Function      : addTimedVault
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This creates a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability allows miners to manipulate block timestamps to bypass the intended 24-hour waiting period between vault updates. An attacker with mining power could: 1) Call addTimedVault() to set a pending vault, 2) Mine blocks with manipulated timestamps to make it appear that sufficient time has passed, 3) Call confirmTimedVault() prematurely to add vaults that should not be available yet. This requires state persistence between transactions (lastVaultUpdate and pendingVaultAmount mappings) and multiple function calls to exploit.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public lastVaultUpdate;
    mapping(address => uint256) public pendingVaultAmount;

    function addTimedVault(address wallet, uint256 amount) public onlyOwner {
        // Check if enough time has passed since last vault update (24 hours)
        require(now - lastVaultUpdate[wallet] >= 86400, "Must wait 24 hours between vault updates");
        // Store pending amount and timestamp
        pendingVaultAmount[wallet] = amount;
        lastVaultUpdate[wallet] = now;
    }

    function confirmTimedVault(address wallet) public onlyOwner {
        // Vulnerable: Only checks if 1 hour has passed, but miners can manipulate timestamp
        require(now - lastVaultUpdate[wallet] >= 3600, "Must wait 1 hour to confirm vault");
        require(pendingVaultAmount[wallet] > 0, "No pending vault amount");
        // Add the vault with current timestamp as unfrozen time
        vaults.push(Vault(wallet, pendingVaultAmount[wallet], now));
        // Clear pending amount
        pendingVaultAmount[wallet] = 0;
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

/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the proposedOwner before updating the owner state. This creates a classic Checks-Effects-Interactions violation where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `proposedOwner.call()` before the state update
 * 2. The call invokes `onOwnershipAccepted(address)` callback on the new owner
 * 3. State update (`owner = proposedOwner`) happens AFTER the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker gets themselves set as `proposedOwner` (via social engineering or compromised current owner)
 * 2. **Transaction 2**: Attacker calls `acceptOwnership()` from a malicious contract that implements `onOwnershipAccepted()`
 * 3. **During the callback**: The external call occurs while `owner` is still the old value, allowing the attacker to re-enter owner-restricted functions like `withdraw()`, `setLottery()`, `setAdmin()`, or `destruct()`
 * 4. **State inconsistency**: The attacker can exploit owner privileges while the ownership transfer is still in progress
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior state setup (proposedOwner must be set in previous transaction)
 * - The actual exploitation happens during the callback in the acceptOwnership transaction
 * - The attacker needs to have a contract deployed that can receive the callback and perform reentrancy
 * - The exploit leverages the accumulated state from previous transactions (proposedOwner being set) combined with the timing window during the external call
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world ownership transfer patterns where contracts notify stakeholders about important state changes, making it a subtle but dangerous vulnerability that could easily be missed in code reviews.
 */
pragma solidity ^0.4.13;

contract EthereumLottery {
    function admin() constant returns (address);
    function needsInitialization() constant returns (bool);
    function initLottery(uint _jackpot, uint _numTickets,
                         uint _ticketPrice, int _durationInBlocks) payable;
    function needsFinalization() constant returns (bool);
    function finalizeLottery(uint _steps);
}

contract LotteryAdmin {
    address public owner;
    address public admin;
    address public proposedOwner;

    address public ethereumLottery;

    event Deposit(address indexed _from, uint _value);

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier onlyAdminOrOwner {
        require(msg.sender == owner || msg.sender == admin);
        _;
    }

    function LotteryAdmin(address _ethereumLottery) {
        owner = msg.sender;
        admin = msg.sender;
        ethereumLottery = _ethereumLottery;
    }

    function () payable {
        Deposit(msg.sender, msg.value);
    }

    function needsAdministration() constant returns (bool) {
        if (EthereumLottery(ethereumLottery).admin() != address(this)) {
            return false;
        }

        return EthereumLottery(ethereumLottery).needsFinalization();
    }

    function administrate(uint _steps) {
        EthereumLottery(ethereumLottery).finalizeLottery(_steps);
    }

    function initLottery(uint _jackpot, uint _numTickets,
                         uint _ticketPrice, int _durationInBlocks)
             onlyAdminOrOwner {
        EthereumLottery(ethereumLottery).initLottery.value(_jackpot)(
            _jackpot, _numTickets, _ticketPrice, _durationInBlocks);
    }

    function withdraw(uint _value) onlyOwner {
        owner.transfer(_value);
    }

    function setLottery(address _ethereumLottery) onlyOwner {
        ethereumLottery = _ethereumLottery;
    }

    function setAdmin(address _admin) onlyOwner {
        admin = _admin;
    }

    function proposeOwner(address _owner) onlyOwner {
        proposedOwner = _owner;
    }

    function acceptOwnership() {
        require(proposedOwner != 0);
        require(msg.sender == proposedOwner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the new owner about ownership transfer (vulnerable external call)
        if (proposedOwner.call(bytes4(keccak256("onOwnershipAccepted(address)")), owner)) {
            // External call success - callback could re-enter other functions
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = proposedOwner;
    }

    function destruct() onlyOwner {
        selfdestruct(owner);
    }
}
/*
 * ===== SmartInject Injection Details =====
 * Function      : proposeOwner
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `pendingProposals` mapping to track pending ownership proposals
 *    - `proposalCount` to maintain proposal statistics
 * 
 * 2. **Vulnerable External Call**: Added `_owner.call()` to notify the proposed owner before finalizing the state change. This creates a reentrancy window where the malicious contract can call back into the function.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `proposeOwner()` with malicious contract address
 *    - **During TX1**: The external call triggers the malicious contract's fallback/`onOwnershipProposed()` function
 *    - **Reentrancy**: Malicious contract calls back into `proposeOwner()` with different addresses while `pendingProposals` state is inconsistent
 *    - **Transaction 2**: Attacker calls `acceptOwnership()` to complete the ownership transfer with manipulated state
 * 
 * 4. **State Corruption**: The vulnerability allows manipulation of `proposalCount` and `pendingProposals` across multiple calls, potentially enabling the attacker to:
 *    - Inflate proposal counts
 *    - Set multiple pending proposals simultaneously
 *    - Bypass intended single-proposal logic
 * 
 * 5. **Why Multi-Transaction**: The vulnerability requires the external call callback to manipulate state, then a separate transaction to `acceptOwnership()` to complete the exploit. The state corruption persists between transactions, making this a true multi-transaction vulnerability.
 * 
 * The code maintains the original function's purpose while introducing a realistic vulnerability that could appear in production code attempting to implement ownership proposal notifications.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingProposals;
    uint256 public proposalCount;
    
    function proposeOwner(address _owner) onlyOwner {
        // Mark proposal as pending before external call
        pendingProposals[_owner] = true;
        proposalCount++;
        
        // External call to notify the proposed owner - vulnerable to reentrancy
        if (_owner.call.gas(10000)(bytes4(keccak256("onOwnershipProposed(address)")), address(this))) {
            // Success - finalize the proposal
            proposedOwner = _owner;
            pendingProposals[_owner] = false;
        } else {
            // Revert proposal state on failure
            pendingProposals[_owner] = false;
            proposalCount--;
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function acceptOwnership() {
        require(proposedOwner != 0);
        require(msg.sender == proposedOwner);
        owner = proposedOwner;
    }

    function destruct() onlyOwner {
        selfdestruct(owner);
    }
}
/*
 * ===== SmartInject Injection Details =====
 * Function      : initLottery
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Callback**: Introduced a callback mechanism via `ethereumLottery.call()` that allows the external lottery contract to call back into the LotteryAdmin contract during initialization.
 * 
 * 2. **State Update Timing**: The vulnerability occurs because state-dependent operations happen after external calls, creating a window for reentrancy.
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker calls `initLottery()` with malicious lottery contract address
 *    - **Transaction 2**: During the callback, the malicious contract calls back into `initLottery()` again
 *    - **Transaction 3**: The reentrant call can drain funds or manipulate state before the first call completes
 *    - **State Accumulation**: Each call persists state changes in contract balance and lottery state
 * 
 * 4. **Stateful Nature**: The vulnerability requires:
 *    - Multiple lottery initialization calls to build up exploitable state
 *    - Contract balance accumulation across transactions
 *    - Persistent state in the external lottery contract between calls
 * 
 * 5. **Realistic Exploitation Scenario**:
 *    - Attacker deploys malicious lottery contract
 *    - Calls `setLottery()` to point to malicious contract (if owner/admin)
 *    - Calls `initLottery()` multiple times with increasing jackpots
 *    - Each call allows reentrancy during the callback phase
 *    - Funds are drained across multiple initialization cycles
 * 
 * The vulnerability is subtle and realistic because callback mechanisms in lottery systems are common for status reporting and event handling.
 */
pragma solidity ^0.4.13;

contract EthereumLottery {
    address public ethereumLottery;

    modifier onlyAdminOrOwner {
        require(msg.sender == address(0)); // Placeholder; actual logic should be in derived contract
        _;
    }

    function admin() public constant returns (address);
    function needsInitialization() public constant returns (bool);
    function initLottery(uint _jackpot, uint _numTickets,
                     // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                     uint _ticketPrice, int _durationInBlocks)
         public onlyAdminOrOwner payable {
    // Execute external call before state updates
    EthereumLottery(ethereumLottery).initLottery.value(_jackpot)(
        _jackpot, _numTickets, _ticketPrice, _durationInBlocks);
    
    // Add callback mechanism that allows reentrancy
    // This simulates a lottery contract that calls back to report initialization status
    if (ethereumLottery.call(bytes4(keccak256("onLotteryInitialized(address,uint256)")), this, _jackpot)) {
        // Callback succeeded - this creates a reentrancy vector
        // The external contract can call back into any function during this callback
    }
    
    // Update state after external calls - this is where the vulnerability lies
    // In a reentrant scenario, this contract's balance might be manipulated
    // before this state update occurs
    address(this).balance; // This balance check happens after external calls
                     // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}
    function needsFinalization() public constant returns (bool);
    function finalizeLottery(uint _steps) public;
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

    constructor(address _ethereumLottery) public {
        owner = msg.sender;
        admin = msg.sender;
        ethereumLottery = _ethereumLottery;
    }

    function () public payable {
        Deposit(msg.sender, msg.value);
    }

    function needsAdministration() public constant returns (bool) {
        if (EthereumLottery(ethereumLottery).admin() != address(this)) {
            return false;
        }

        return EthereumLottery(ethereumLottery).needsFinalization();
    }

    function administrate(uint _steps) public {
        EthereumLottery(ethereumLottery).finalizeLottery(_steps);
    }

    function initLottery(uint _jackpot, uint _numTickets,
                         uint _ticketPrice, int _durationInBlocks)
             public onlyAdminOrOwner payable {
        EthereumLottery(ethereumLottery).initLottery.value(_jackpot)(
            _jackpot, _numTickets, _ticketPrice, _durationInBlocks);
    }

    function withdraw(uint _value) public onlyOwner {
        owner.transfer(_value);
    }

    function setLottery(address _ethereumLottery) public onlyOwner {
        ethereumLottery = _ethereumLottery;
    }

    function setAdmin(address _admin) public onlyOwner {
        admin = _admin;
    }

    function proposeOwner(address _owner) public onlyOwner {
        proposedOwner = _owner;
    }

    function acceptOwnership() public {
        require(proposedOwner != address(0));
        require(msg.sender == proposedOwner);
        owner = proposedOwner;
    }

    function destruct() public onlyOwner {
        selfdestruct(owner);
    }
}

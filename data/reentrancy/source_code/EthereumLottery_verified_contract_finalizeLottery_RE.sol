/*
 * ===== SmartInject Injection Details =====
 * Function      : finalizeLottery
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **Stateful Multi-Transaction Reentrancy Vulnerability Injection**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables for Multi-Transaction Tracking:**
 *    - `mapping(address => bool) public finalizationInProgress` - Tracks ongoing finalization processes
 *    - `mapping(address => uint) public stepsCompleted` - Accumulates steps across multiple transactions
 *    - `mapping(address => bool) public prizesDistributed` - Tracks prize distribution status
 *    - `bool public finalizationComplete` - Global finalization status
 * 
 * 2. **Introduced Winner Notification Callback Interface:**
 *    - `IWinnerNotifier` interface for external winner notification
 *    - This creates an attack vector through user-controlled contract callbacks
 * 
 * 3. **Implemented Vulnerable Checks-Effects-Interactions Pattern:**
 *    - External calls to `EthereumLottery(ethereumLottery).finalizeLottery(_steps)` occur first
 *    - External calls to `IWinnerNotifier(winner).notifyWinner()` happen before state updates
 *    - Critical state updates (`prizesDistributed[msg.sender] = true`) happen AFTER external calls
 * 
 * 4. **Created Multi-Transaction Exploitation Logic:**
 *    - Function requires multiple calls with accumulated `_steps` to reach vulnerability trigger (>= 10 steps)
 *    - State persists between transactions through mapping variables
 *    - Incremental step processing allows gradual state buildup
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * **Transaction 1-N (Building State):**
 * - Attacker calls `finalizeLottery()` with small step values (e.g., 3 steps each)
 * - State accumulates: `stepsCompleted[attacker]` increases from 0 → 3 → 6 → 9
 * - `finalizationInProgress[attacker]` remains true
 * - No vulnerability triggered yet as `stepsCompleted < 10`
 * 
 * **Transaction N+1 (Triggering Vulnerability):**
 * - Attacker calls `finalizeLottery(2)` to reach `stepsCompleted[attacker] = 11`
 * - Condition `targetSteps >= 10 && !prizesDistributed[msg.sender]` is met
 * - External call to `EthereumLottery(ethereumLottery).finalizeLottery()` is made
 * - **CRITICAL**: External call to attacker's `IWinnerNotifier` contract occurs
 * - Attacker's malicious contract receives `notifyWinner()` callback
 * - State variables `prizesDistributed` and `finalizationComplete` are still false
 * 
 * **Transaction N+2 (Reentrant Exploitation):**
 * - From within `notifyWinner()` callback, attacker reenters `finalizeLottery()`
 * - `prizesDistributed[attacker]` is still false (not yet updated)
 * - `finalizationComplete` is still false
 * - Attacker can exploit inconsistent state to trigger multiple prize distributions
 * - Each reentrant call can potentially claim prizes before state is properly updated
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation Dependency**: The vulnerability only triggers when `stepsCompleted >= 10`, requiring multiple transactions to build up the necessary state.
 * 
 * 2. **Persistent State Between Transactions**: The `finalizationInProgress` and `stepsCompleted` mappings maintain state across transaction boundaries, making single-transaction exploitation impossible.
 * 
 * 3. **Incremental Processing Logic**: The function processes steps incrementally, requiring multiple calls to reach the vulnerable code path.
 * 
 * 4. **Race Condition Window**: The multi-transaction nature creates a window where an attacker can build up state legitimately, then exploit the reentrancy vulnerability once the threshold is reached.
 * 
 * 5. **Cross-Transaction State Inconsistency**: The vulnerability exploits the fact that state changes persist between transactions, but the vulnerable external calls only occur after sufficient state accumulation.
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires careful planning across multiple transactions to exploit, making it particularly dangerous as it may not be detected by single-transaction security analysis tools.
 */
pragma solidity ^0.4.13;

contract EthereumLottery {
    function admin() constant returns (address);
    function needsInitialization() constant returns (bool);
    function initLottery(uint _jackpot, uint _numTickets,
                         uint _ticketPrice, int _durationInBlocks) payable;
    function needsFinalization() constant returns (bool);
    // Added missing function for compilation only.
    function finalizeLottery(uint _steps) public;
}

// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
interface IWinnerNotifier {
    function notifyWinner(address winner, uint prize) external;
}

contract VulnerableLottery {
    // Add state variables for tracking finalization progress
    mapping(address => bool) public finalizationInProgress;
    mapping(address => uint) public stepsCompleted;
    mapping(address => bool) public prizesDistributed;
    bool public finalizationComplete;
    address public ethereumLottery;

    // Vulnerable function
    function finalizeLottery(uint _steps) public {
        if (!finalizationInProgress[msg.sender]) {
            finalizationInProgress[msg.sender] = true;
            stepsCompleted[msg.sender] = 0;
        }

        uint currentSteps = stepsCompleted[msg.sender];
        uint targetSteps = currentSteps + _steps;

        if (targetSteps >= 10 && !prizesDistributed[msg.sender]) {
            // External call to lottery contract that could trigger reentrancy
            EthereumLottery(ethereumLottery).finalizeLottery(_steps);

            // Vulnerable: External call before updating prize state
            address winner = getWinner(); // Assume this returns a winner address
            if (winner != address(0)) {
                // Vulnerable to reentrancy
                // Use low-level call for compatibility with Solidity ^0.4.13
                if (winner.call(bytes4(keccak256("notifyWinner(address,uint256)")), winner, getPrizeAmount())) {
                    // External call succeeded
                } else {
                    // Handle failure silently
                }
            }
            // State update happens AFTER external calls
            prizesDistributed[msg.sender] = true;
            finalizationComplete = true;
        } else {
            EthereumLottery(ethereumLottery).finalizeLottery(_steps);
        }
        stepsCompleted[msg.sender] = targetSteps;
        if (targetSteps >= 100) {
            finalizationInProgress[msg.sender] = false;
            stepsCompleted[msg.sender] = 0;
        }
    }

    function getWinner() internal view returns (address) {
        return address(0x123);
    }
    function getPrizeAmount() internal view returns (uint) {
        return 1 ether;
    }
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        // Call to potentially vulnerable finalizeLottery
        VulnerableLottery(ethereumLottery).finalizeLottery(_steps);
    }

    function initLottery(uint _jackpot, uint _numTickets,
                         uint _ticketPrice, int _durationInBlocks)
             public onlyAdminOrOwner {
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
        require(proposedOwner != 0);
        require(msg.sender == proposedOwner);
        owner = proposedOwner;
    }

    function destruct() public onlyOwner {
        selfdestruct(owner);
    }
}

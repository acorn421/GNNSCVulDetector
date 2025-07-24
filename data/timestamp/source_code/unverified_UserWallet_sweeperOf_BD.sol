/*
 * ===== SmartInject Injection Details =====
 * Function      : sweeperOf
 * Vulnerability : Timestamp Dependence
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
 * This injection introduces a stateful, multi-transaction Timestamp Dependence vulnerability through a time-based temporary sweeper override mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * **Vulnerability Details:**
 * 1. **State Variables Added**: Two new mappings store timestamp-based state that persists between transactions
 * 2. **Critical Timestamp Logic**: Uses block.timestamp for determining if temporary sweepers are active
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker calls sweeperOf() to trigger timestamp storage in lastSweeperChangeTime
 *    - Transaction 2: Attacker manipulates block.timestamp (via miner control or waiting) 
 *    - Transaction 3: Attacker calls sweeperOf() again to exploit the timestamp-dependent logic
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * - **Scenario 1**: Attacker with mining capabilities can manipulate timestamps between calls to activate different sweepers
 * - **Scenario 2**: Attacker can time their calls around natural timestamp changes to exploit the 1-hour window logic
 * - **Scenario 3**: Multiple attackers can coordinate to exploit the persistent state stored in lastSweeperChangeTime
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Persistence**: The vulnerability relies on timestamps stored in previous calls (lastSweeperChangeTime)
 * 2. **Time-Based Logic**: The 1-hour window check requires time to pass between transactions
 * 3. **Temporal Sequence**: The exploit depends on the sequence and timing of multiple function calls
 * 4. **State Accumulation**: Each call potentially modifies the stored timestamp state for future exploitation
 * 
 * This creates a realistic vulnerability where attackers must plan and execute multiple transactions over time to exploit the timestamp-dependent logic.
 */
pragma solidity ^0.4.12;

// Forward declarations replaced with interfaces for type safety
interface Controller {
    function authorizedCaller() external returns (address);
    function owner() external returns (address);
    function halted() external returns (bool);
    function destination() external returns (address);
    function logSweep(address from, address to, address token, uint amount) external;
}

interface AbstractSweeperList {
    function sweeperOf(address _token) external returns (address);
}

contract AbstractSweeper {
    function sweep(address token, uint amount) public returns (bool);

    function () public { throw; }

    Controller controller;

    function AbstractSweeper(address _controller) public {
        controller = Controller(_controller);
    }

    modifier canSweep() {
        if (msg.sender != controller.authorizedCaller() && msg.sender != controller.owner()) throw;
        if (controller.halted()) throw;
        _;
    }
}

contract Token {
    function balanceOf(address a) public returns (uint) {
        (a);
        return 0;
    }

    function transfer(address a, uint val) public returns (bool) {
        (a);
        (val);
        return false;
    }
}

contract DefaultSweeper is AbstractSweeper {
    function DefaultSweeper(address controller)
             AbstractSweeper(controller) public {}

    function sweep(address _token, uint _amount)
    canSweep
    public
    returns (bool) {
        bool success = false;
        address destination = controller.destination();

        if (_token != address(0)) {
            Token token = Token(_token);
            uint amount = _amount;
            if (amount > token.balanceOf(this)) {
                return false;
            }

            success = token.transfer(destination, amount);
        }
        else {
            uint amountInWei = _amount;
            if (amountInWei > this.balance) {
                return false;
            }

            success = destination.send(amountInWei);
        }

        if (success) {
            controller.logSweep(this, destination, _token, _amount);
        }
        return success;
    }
}

contract UserWallet {
    AbstractSweeperList sweeperList;
    function UserWallet(address _sweeperlist) public {
        sweeperList = AbstractSweeperList(_sweeperlist);
    }

    function () public payable { }

    function tokenFallback(address _from, uint _value, bytes _data) public {
        (_from);
        (_value);
        (_data);
     }

    function sweep(address _token, uint _amount)
    public
    returns (bool) {
        (_amount);
        return sweeperList.sweeperOf(_token).delegatecall(msg.data);
    }
}

contract AbstractSweeperList {
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    mapping (address => uint) public lastSweeperChangeTime;
    mapping (address => address) public temporarySweepers;
    mapping (address => address) sweepers;
    address public defaultSweeper;

    function sweeperOf(address _token) public returns (address) {
        address sweeper = sweepers[_token];
        
        // Time-based temporary sweeper override mechanism
        if (temporarySweepers[_token] != address(0)) {
            uint changeTime = lastSweeperChangeTime[_token];
            // Vulnerable: Using block.timestamp for critical logic
            // If current time is within 1 hour of change, use temporary sweeper
            if (block.timestamp - changeTime < 3600) {
                sweeper = temporarySweepers[_token];
            } else {
                // Clear expired temporary sweeper
                temporarySweepers[_token] = address(0);
                lastSweeperChangeTime[_token] = 0;
            }
        }
        
        // Store timestamp for potential future temporary sweeper activation
        if (sweeper == address(0)) {
            sweeper = defaultSweeper;
            // Vulnerable: Store block.timestamp in state for later use
            lastSweeperChangeTime[_token] = block.timestamp;
        }
        
        return sweeper;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
}

contract Controller is AbstractSweeperList {
    address public owner;
    address public authorizedCaller;

    address public destination;

    bool public halted;

    event LogNewWallet(address receiver);
    event LogSweep(address indexed from, address indexed to, address indexed token, uint amount);
    
    modifier onlyOwner() {
        if (msg.sender != owner) throw; 
        _;
    }

    modifier onlyAuthorizedCaller() {
        if (msg.sender != authorizedCaller) throw; 
        _;
    }

    modifier onlyAdmins() {
        if (msg.sender != authorizedCaller && msg.sender != owner) throw; 
        _;
    }

    function Controller() public
    {
        owner = msg.sender;
        destination = msg.sender;
        authorizedCaller = msg.sender;
        defaultSweeper = address(new DefaultSweeper(this));
    }

    function changeAuthorizedCaller(address _newCaller) public onlyOwner {
        authorizedCaller = _newCaller;
    }

    function changeDestination(address _dest) public onlyOwner {
        destination = _dest;
    }

    function changeOwner(address _owner) public onlyOwner {
        owner = _owner;
    }

    function makeWallet() public onlyAdmins returns (address wallet)  {
        wallet = address(new UserWallet(this));
        LogNewWallet(wallet);
    }

    function halt() public onlyAdmins {
        halted = true;
    }

    function start() public onlyOwner {
        halted = false;
    }

    function addSweeper(address _token, address _sweeper) public onlyOwner {
        sweepers[_token] = _sweeper;
    }

    function sweeperOf(address _token) public returns (address) {
        address sweeper = sweepers[_token];
        if (sweeper == 0) sweeper = defaultSweeper;
        return sweeper;
    }

    function logSweep(address from, address to, address token, uint amount) public {
        LogSweep(from, to, token, amount);
    }
}

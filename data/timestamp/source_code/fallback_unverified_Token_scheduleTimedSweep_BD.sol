/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedSweep
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where the execution of scheduled sweeps relies on block.timestamp (now). The vulnerability is stateful and multi-transaction because: 1) First, an admin schedules a sweep with scheduleTimedSweep(), creating persistent state; 2) Later, executeTimedSweep() is called in a separate transaction, relying on block.timestamp for timing validation; 3) Malicious miners can manipulate timestamps to either delay or prematurely execute sweeps, potentially affecting the timing of fund transfers. The vulnerability requires multiple transactions and state persistence between calls.
 */
pragma solidity ^0.4.12;

contract AbstractSweeper {
    function sweep(address token, uint amount) returns (bool);

    function () { throw; }

    Controller controller;

    function AbstractSweeper(address _controller) {
        controller = Controller(_controller);
    }

    modifier canSweep() {
        if (msg.sender != controller.authorizedCaller() && msg.sender != controller.owner()) throw;
        if (controller.halted()) throw;
        _;
    }
}

contract Token {
    function balanceOf(address a) returns (uint) {
        (a);
        return 0;
    }

    function transfer(address a, uint val) returns (bool) {
        (a);
        (val);
        return false;
    }
}

contract DefaultSweeper is AbstractSweeper {
    function DefaultSweeper(address controller)
             AbstractSweeper(controller) {}

    function sweep(address _token, uint _amount)
    canSweep
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
    function UserWallet(address _sweeperlist) {
        sweeperList = AbstractSweeperList(_sweeperlist);
    }

    function () public payable { }

    function tokenFallback(address _from, uint _value, bytes _data) {
        (_from);
        (_value);
        (_data);
     }

    function sweep(address _token, uint _amount)
    returns (bool) {
        (_amount);
        return sweeperList.sweeperOf(_token).delegatecall(msg.data);
    }
}

contract AbstractSweeperList {
    function sweeperOf(address _token) returns (address);
}

contract Controller is AbstractSweeperList {
    address public owner;
    address public authorizedCaller;

    address public destination;

    bool public halted;

    event LogNewWallet(address receiver);
    event LogSweep(address indexed from, address indexed to, address indexed token, uint amount);
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timed sweeps
    struct TimedSweep {
        address token;
        uint amount;
        address from;
        uint scheduledTime;
        bool executed;
    }
    
    mapping(uint => TimedSweep) public timedSweeps;
    uint public sweepCounter;
    
    // === END FALLBACK INJECTION ===

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

    function Controller() 
    {
        owner = msg.sender;
        destination = msg.sender;
        authorizedCaller = msg.sender;
    }

    function changeAuthorizedCaller(address _newCaller) onlyOwner {
        authorizedCaller = _newCaller;
    }

    function changeDestination(address _dest) onlyOwner {
        destination = _dest;
    }

    function changeOwner(address _owner) onlyOwner {
        owner = _owner;
    }

    function makeWallet() onlyAdmins returns (address wallet)  {
        wallet = address(new UserWallet(this));
        LogNewWallet(wallet);
    }

    function halt() onlyAdmins {
        halted = true;
    }

    function start() onlyOwner {
        halted = false;
    }

    address public defaultSweeper = address(new DefaultSweeper(this));
    mapping (address => address) sweepers;

    function addSweeper(address _token, address _sweeper) onlyOwner {
        sweepers[_token] = _sweeper;
    }

    function sweeperOf(address _token) returns (address) {
        address sweeper = sweepers[_token];
        if (sweeper == 0) sweeper = defaultSweeper;
        return sweeper;
    }

    function logSweep(address from, address to, address token, uint amount) {
        LogSweep(from, to, token, amount);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Schedule a sweep to be executed at a specific time
    function scheduleTimedSweep(address _token, uint _amount, address _from, uint _executionTime) onlyAdmins returns (uint sweepId) {
        require(_executionTime > now);
        
        sweepCounter++;
        sweepId = sweepCounter;
        
        timedSweeps[sweepId] = TimedSweep({
            token: _token,
            amount: _amount,
            from: _from,
            scheduledTime: _executionTime,
            executed: false
        });
        
        return sweepId;
    }
    
    // Execute a previously scheduled sweep (vulnerable to timestamp manipulation)
    function executeTimedSweep(uint _sweepId) onlyAdmins {
        TimedSweep storage sweep = timedSweeps[_sweepId];
        require(!sweep.executed);
        
        // Vulnerable: relying on block.timestamp for critical timing
        if (now >= sweep.scheduledTime) {
            sweep.executed = true;
            
            // Perform the sweep
            address sweeper = sweeperOf(sweep.token);
            UserWallet(sweep.from).sweep(sweep.token, sweep.amount);
            
            logSweep(sweep.from, destination, sweep.token, sweep.amount);
        }
    }
    
    // Allow rescheduling of pending sweeps (adds to multi-transaction nature)
    function rescheduleTimedSweep(uint _sweepId, uint _newExecutionTime) onlyAdmins {
        TimedSweep storage sweep = timedSweeps[_sweepId];
        require(!sweep.executed);
        require(_newExecutionTime > now);
        
        sweep.scheduledTime = _newExecutionTime;
    }
    // === END FALLBACK INJECTION ===
}

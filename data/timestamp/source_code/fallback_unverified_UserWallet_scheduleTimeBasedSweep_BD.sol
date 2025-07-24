/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimeBasedSweep
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The contract allows scheduling sweeps for future execution based on block timestamps, but miners can manipulate block timestamps within a ~900 second window. An attacker must: 1) First call scheduleTimeBasedSweep() to create a scheduled sweep, 2) Wait for the scheduled time, 3) Call executeScheduledSweep() when they can influence the block timestamp. The vulnerability requires multiple transactions and persistent state (the scheduledSweeps mapping) to exploit.
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
    // This function was added as a fallback when existing functions failed injection
    struct ScheduledSweep {
        address token;
        uint amount;
        uint scheduledTime;
        bool executed;
    }
    
    mapping(address => ScheduledSweep) public scheduledSweeps;
    
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
    
    function scheduleTimeBasedSweep(address _wallet, address _token, uint _amount, uint _delaySeconds) onlyAdmins {
        require(_delaySeconds > 0);
        require(_amount > 0);
        
        scheduledSweeps[_wallet] = ScheduledSweep({
            token: _token,
            amount: _amount,
            scheduledTime: now + _delaySeconds,
            executed: false
        });
    }
    
    function executeScheduledSweep(address _wallet) onlyAdmins returns (bool) {
        ScheduledSweep storage sweep = scheduledSweeps[_wallet];
        require(!sweep.executed);
        require(sweep.scheduledTime != 0);
        
        // Vulnerable: Uses block.timestamp (now) for time comparison
        // Miners can manipulate timestamp within ~900 second window
        if (now >= sweep.scheduledTime) {
            sweep.executed = true;
            
            // Execute the sweep through the wallet
            UserWallet wallet = UserWallet(_wallet);
            bool success = wallet.sweep(sweep.token, sweep.amount);
            
            if (success) {
                logSweep(_wallet, destination, sweep.token, sweep.amount);
            }
            
            return success;
        }
        
        return false;
    }
    // === END FALLBACK INJECTION ===

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
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : changeOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-locked ownership change mechanism. The vulnerability requires multiple transactions over time and depends on block.timestamp for critical security logic.
 * 
 * **Specific Changes Made:**
 * 1. Added state variables (pendingOwner, ownershipChangeTime) to track ownership transition
 * 2. Implemented time-based delay using block.timestamp + 24 hours
 * 3. Created multi-stage ownership change process requiring separate transactions
 * 4. Used block.timestamp directly in critical access control logic without validation
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires a sequence of transactions:
 * - Transaction 1: Owner calls changeOwner() to initiate change (sets pendingOwner and ownershipChangeTime)
 * - Transaction 2: After 24 hours, owner calls changeOwner() again to complete the change
 * - Exploitation: Miners can manipulate block.timestamp to accelerate or delay ownership changes
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability depends on ownershipChangeTime state persisting between transactions
 * 2. **Time Delay**: The 24-hour delay forces multiple transactions separated by time
 * 3. **Sequence Dependency**: Each transaction has different behavior based on current state and timestamp
 * 4. **Accumulative Effect**: The vulnerability's impact builds through the sequence of state changes
 * 
 * **Realistic Attack Scenarios:**
 * - Miners could manipulate timestamps to bypass the 24-hour delay
 * - Attackers could exploit timing windows during ownership transitions
 * - Block timestamp manipulation could lead to unexpected ownership changes at wrong times
 */
pragma solidity ^0.4.12;

contract AbstractSweeper {
    function sweep(address token, uint amount) returns (bool);

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
             AbstractSweeper(controller) public {}

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

    // Variables to support the timestamp dependence vulnerability
    address public pendingOwner;
    uint public ownershipChangeTime;

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
    }

    function changeAuthorizedCaller(address _newCaller) onlyOwner public {
        authorizedCaller = _newCaller;
    }

    function changeDestination(address _dest) onlyOwner public {
        destination = _dest;
    }

    function changeOwner(address _owner) onlyOwner public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        if (ownershipChangeTime == 0) {
            // First time setting up ownership change
            pendingOwner = _owner;
            ownershipChangeTime = block.timestamp + 24 hours;
        } else if (block.timestamp >= ownershipChangeTime) {
            // Time delay has passed, complete the ownership change
            owner = pendingOwner;
            pendingOwner = address(0);
            ownershipChangeTime = 0;
        } else {
            // Update pending owner if called again before time delay
            pendingOwner = _owner;
            ownershipChangeTime = block.timestamp + 24 hours;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function makeWallet() onlyAdmins public returns (address wallet)  {
        wallet = address(new UserWallet(this));
        LogNewWallet(wallet);
    }

    function halt() onlyAdmins public {
        halted = true;
    }

    function start() onlyOwner public {
        halted = false;
    }

    address public defaultSweeper = address(new DefaultSweeper(this));
    mapping (address => address) sweepers;

    function addSweeper(address _token, address _sweeper) onlyOwner public {
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

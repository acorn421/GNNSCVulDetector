/*
 * ===== SmartInject Injection Details =====
 * Function      : sweep
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `pendingSweeps`: Tracks ongoing sweep operations per token per user
 *    - `totalSweptByToken`: Accumulates total amounts swept per token
 *    - `sweepInProgress`: Tracks if a sweep is currently in progress
 * 
 * 2. **Vulnerable State Management**: 
 *    - State tracking occurs before external calls
 *    - State updates happen AFTER external calls (violating checks-effects-interactions)
 *    - State persists across transactions, enabling multi-step exploitation
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `sweep()` → `sweepInProgress[token] = true`, `pendingSweeps[token][attacker] = amount`
 *    - **During token.transfer()**: Attacker's malicious token contract re-enters `sweep()`
 *    - **Transaction 2**: Second call sees stale state, bypasses the `sweepInProgress` check since it's already true
 *    - **Exploitation**: Balance checks use stale values, allowing double-spending across the transaction sequence
 * 
 * 4. **Why Multi-Transaction**: 
 *    - The vulnerability requires the persistent state from the first transaction (`sweepInProgress`, `pendingSweeps`)
 *    - Reentrancy during external calls allows manipulation of the state tracking
 *    - Subsequent transactions can exploit the inconsistent state that persists between calls
 *    - The accumulated state in `totalSweptByToken` can be manipulated across multiple sweep operations
 * 
 * 5. **Realistic Integration**: The state tracking appears as a legitimate feature for monitoring sweep operations, making the vulnerability subtle and realistic.
 */
pragma solidity ^0.4.12;

contract AbstractSweeper {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => mapping(address => uint)) public pendingSweeps;
mapping(address => uint) public totalSweptByToken;
mapping(address => bool) public sweepInProgress;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function sweep(address _token, uint _amount)
    canSweep
    returns (bool) {
        bool success = false;
        address destination = controller.destination();

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Track sweep initiation - state persists across transactions
        if (!sweepInProgress[_token]) {
            sweepInProgress[_token] = true;
            pendingSweeps[_token][msg.sender] = _amount;
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (_token != address(0)) {
            Token token = Token(_token);
            uint amount = _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Vulnerable check: uses stale balance during reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            if (amount > token.balanceOf(this)) {
                return false;
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // VULNERABILITY: External call before state updates
            success = token.transfer(destination, amount);
            
            // State updates after external call - can be manipulated via reentrancy
            if (success) {
                totalSweptByToken[_token] += amount;
                // Only clear if this is the original sweep amount
                if (pendingSweeps[_token][msg.sender] == amount) {
                    delete pendingSweeps[_token][msg.sender];
                    sweepInProgress[_token] = false;
                }
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
        else {
            uint amountInWei = _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Vulnerable check: uses stale balance during reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            if (amountInWei > this.balance) {
                return false;
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // VULNERABILITY: External call before state updates
            success = destination.send(amountInWei);
            
            // State updates after external call - exploitable via reentrancy
            if (success) {
                totalSweptByToken[_token] += amountInWei;
                // Only clear if this is the original sweep amount
                if (pendingSweeps[_token][msg.sender] == amountInWei) {
                    delete pendingSweeps[_token][msg.sender];
                    sweepInProgress[_token] = false;
                }
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }

        if (success) {
            controller.logSweep(this, destination, _token, _amount);
        }
        return success;
    }

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
}
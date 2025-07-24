/*
 * ===== SmartInject Injection Details =====
 * Function      : tokenFallback
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `tokenBalances`: Tracks cumulative token deposits per user
 *    - `depositNotifiers`: Maps users to their notification contracts
 *    - `processingDeposit`: Prevents immediate recursion but allows multi-transaction exploitation
 * 
 * 2. **Vulnerable Pattern**: External call to user-controlled contract (`depositNotifiers[_from]`) occurs BEFORE state updates (`tokenBalances[_from] += _value`), creating classic reentrancy vulnerability.
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: User sets up malicious notification contract via `depositNotifiers[user] = maliciousContract`
 *    - **Transaction 2**: Token transfer triggers `tokenFallback`, which calls malicious contract
 *    - **Transaction 3**: Malicious contract's `onTokenDeposit` callback transfers more tokens, re-triggering `tokenFallback`
 *    - **Exploitation**: Since `processingDeposit` is cleared after each transaction, the attacker can repeatedly re-enter across multiple transactions, accumulating inflated `tokenBalances` while only depositing tokens once
 * 
 * 4. **Stateful Requirement**: The vulnerability requires:
 *    - Prior state setup (notification contract registration)
 *    - Persistent state between transactions (`tokenBalances` accumulation)
 *    - Cannot be exploited in single transaction due to `processingDeposit` guard
 * 
 * 5. **Real-World Relevance**: Based on actual vulnerabilities in token wallet contracts where notification mechanisms created reentrancy attack vectors.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public tokenBalances;
mapping(address => address) public depositNotifiers;
mapping(address => bool) public processingDeposit;

function tokenFallback(address _from, uint _value, bytes _data) {
    // Check if we're already processing a deposit for this user
    if (processingDeposit[_from]) {
        return;
    }
    
    // Set processing flag
    processingDeposit[_from] = true;
    
    // External call to notify about deposit BEFORE updating state
    // This creates the reentrancy vulnerability
    if (depositNotifiers[_from] != address(0)) {
        // Call to user-controlled contract - vulnerable to reentrancy
        depositNotifiers[_from].call(bytes4(keccak256("onTokenDeposit(address,uint256)")), _from, _value);
    }
    
    // State update happens AFTER external call - classic reentrancy pattern
    tokenBalances[_from] += _value;
    
    // Clear processing flag
    processingDeposit[_from] = false;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
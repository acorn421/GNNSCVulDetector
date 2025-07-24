/*
 * ===== SmartInject Injection Details =====
 * Function      : EnterCode
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
 * This injection introduces a multi-transaction timestamp dependence vulnerability by implementing a time-window based access control system. The vulnerability requires users to make two separate transactions: first to register their timestamp window, then to claim tokens within the same hourly window. This creates multiple attack vectors:
 * 
 * 1. **Miner Timestamp Manipulation**: Miners can manipulate block.timestamp by ±900 seconds to extend time windows
 * 2. **Front-running with Timestamp Control**: Attackers can observe pending transactions and manipulate their own transaction timing
 * 3. **State Poisoning**: The stored timestamp in _last_distribution can be manipulated across transactions
 * 
 * **Multi-Transaction Exploitation Process**:
 * - Transaction 1: User calls EnterCode() to store their timestamp window in state
 * - Transaction 2: User calls EnterCode() again with correct code to claim tokens
 * - Attack: Miner manipulates timestamps between these transactions to extend eligibility windows or create race conditions
 * 
 * The vulnerability is stateful because it relies on timestamp data persisted in the _last_distribution mapping between transactions, and cannot be exploited in a single atomic transaction since it requires the state setup from the first call.
 */
pragma solidity ^0.4.18;

contract BinksBucks  {
    // Token Vars
    string public constant name = "Binks Bucks";
    string public constant symbol = "BNKS";
    uint8 internal _decimals = 18;
    uint internal _totalSupply = 0;
    mapping(address => uint256) internal _balances;
    mapping(address => mapping (address => uint256)) _allowed;

    // Code Entry Vars
    address internal imperator;
    uint internal _code = 0;
    uint internal _distribution_size = 1000000000000000000000;
    uint internal _max_distributions = 100;
    uint internal _distributions_left = 100;
    uint internal _distribution_number = 0;
    mapping(address => uint256) internal _last_distribution;
    
    function BinksBucks(address bossman) public {
        imperator = msg.sender;
        _balances[this] += 250000000000000000000000000;
        _totalSupply += 250000000000000000000000000;
        _balances[bossman] += 750000000000000000000000000;
        _totalSupply += 750000000000000000000000000;
    }

    function totalSupply() public constant returns (uint) {return _totalSupply;}
    function decimals() public constant returns (uint8) {return _decimals;}
    function balanceOf(address owner) public constant returns (uint) {return _balances[owner];}

    // Helper Functions
    function hasAtLeast(address adr, uint amount) constant internal returns (bool) {
        if (amount <= 0) {return false;}
        return _balances[adr] >= amount;

    }

    function canRecieve(address adr, uint amount) constant internal returns (bool) {
        if (amount <= 0) {return false;}
        uint balance = _balances[adr];
        return (balance + amount > balance);
    }

    function hasAllowance(address proxy, address spender, uint amount) constant internal returns (bool) {
        if (amount <= 0) {return false;}
        return _allowed[spender][proxy] >= amount;
    }

    function canAdd(uint x, uint y) pure internal returns (bool) {
        uint total = x + y;
        if (total > x && total > y) {return true;}
        return false;
    }
    
    // End Helper Functions

    function transfer(address to, uint amount) public returns (bool) {
        require(canRecieve(to, amount));
        require(hasAtLeast(msg.sender, amount));
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        Transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address proxy, address spender) public constant returns (uint) {
        return _allowed[proxy][spender];
    }

    function approve(address spender, uint amount) public returns (bool) {
        _allowed[msg.sender][spender] = amount;
        Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint amount) public returns (bool) {
        require(hasAllowance(msg.sender, from, amount));
        require(canRecieve(to, amount));
        require(hasAtLeast(from, amount));
        _allowed[from][msg.sender] -= amount;
        _balances[from] -= amount;
        _balances[to] += amount;
        Transfer(from, to, amount);
        return true;
    }
    
    function transferEmpire(address newImperator) public {
            require(msg.sender == imperator);
            imperator = newImperator;
        }

    function setCode(uint code) public {
        require(msg.sender == imperator);
        _code = code;
        _distributions_left = _max_distributions;
        _distribution_number += 1;
    }

    function setMaxDistributions(uint num) public {
        require(msg.sender == imperator);
        _max_distributions = num;
    }

    function setDistributionSize(uint num) public {
        require(msg.sender == imperator);
        _distribution_size = num;
    }

    function CodeEligible() public view returns (bool) {
        return (_code != 0 && _distributions_left > 0 && _distribution_number > _last_distribution[msg.sender]);
    }

    function EnterCode(uint code) public {
        require(CodeEligible());
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable timestamp-based access control with state persistence
        uint currentWindow = block.timestamp / 3600; // 1-hour windows
        uint storedWindow = _last_distribution[msg.sender] % 1000000; // Extract stored window
        
        // Multi-transaction vulnerability: First call stores timestamp, subsequent calls validate
        if (_last_distribution[msg.sender] == 0) {
            // First time user - store current time window in state
            _last_distribution[msg.sender] = _distribution_number * 1000000 + currentWindow;
            return; // Exit without distributing tokens
        }
        
        // Subsequent calls: validate against stored timestamp window
        require(currentWindow == storedWindow, "Time window mismatch");
        
        if (code == _code) {
            _last_distribution[msg.sender] = _distribution_number * 1000000 + currentWindow;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            _distributions_left -= 1;
            require(canRecieve(msg.sender, _distribution_size));
            require(hasAtLeast(this, _distribution_size));
            _balances[this] -= _distribution_size;
            _balances[msg.sender] += _distribution_size;
            Transfer(this, msg.sender, _distribution_size);
        }
    }

    event Transfer(address indexed, address indexed, uint);
    event Approval(address indexed proxy, address indexed spender, uint amount);
}
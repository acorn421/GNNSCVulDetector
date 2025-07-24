/*
 * ===== SmartInject Injection Details =====
 * Function      : setCode
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
 * Introduced timestamp dependence vulnerability by adding code activation and expiration times based on block.timestamp. The activation delay uses a modulo operation on block.timestamp creating a predictable but manipulable delay period. This creates multiple exploitation vectors:
 * 
 * 1. **Activation Time Manipulation**: The activation delay (block.timestamp % 256 + 1) creates a predictable window that miners can manipulate by controlling block timestamps within the ~15 second tolerance. Miners can delay or rush block production to ensure favorable activation times.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Imperator calls setCode(), establishing activation and expiration timestamps in contract state
 *    - Transaction 2+: Users monitor blockchain and time their EnterCode() calls to exploit the timestamp-dependent windows
 *    - The vulnerability persists across multiple blocks due to state storage of timestamp values
 * 
 * 3. **Stateful Nature**: The _code_activation_time and _code_expiration_time state variables persist between transactions, creating ongoing vulnerability windows that can be exploited by multiple users across different blocks.
 * 
 * 4. **Realistic Attack Scenarios**:
 *    - Miners can manipulate block timestamps to create favorable activation windows for themselves or allies
 *    - Users can front-run code distributions by predicting activation times based on the modulo calculation
 *    - MEV bots can exploit the predictable timing to gain unfair advantages in token distributions
 * 
 * The vulnerability requires multiple transactions because the timing manipulation happens during setCode() execution but the actual exploitation occurs in subsequent EnterCode() transactions, making it impossible to exploit atomically in a single transaction.
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
    
    // Variables for setCode's timestamp logic
    uint internal _code_activation_time;
    uint internal _code_expiration_time;
    
    constructor(address bossman) public {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store code activation timestamp for time-based validation
        uint activation_delay = (block.timestamp % 256) + 1; // 1-256 second delay
        _code_activation_time = block.timestamp + activation_delay;
        
        // Set code expiration based on block timestamp
        _code_expiration_time = block.timestamp + (3600 * 24); // 24 hour expiration
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        if (code == _code) {
            _last_distribution[msg.sender] = _distribution_number;
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
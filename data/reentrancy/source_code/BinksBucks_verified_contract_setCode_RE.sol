/*
 * ===== SmartInject Injection Details =====
 * Function      : setCode
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled registry contract before state updates. The vulnerability works as follows:
 * 
 * **Transaction 1 (Setup)**: 
 * - Imperator calls setCode() with malicious registry address
 * - External call to codeRegistry.notifyCodeChange() occurs with OLD _distribution_number
 * - Malicious registry reenters setCode() multiple times during this call
 * - Each reentrant call increments _distribution_number but external call still has old value
 * - Creates state inconsistency where _distribution_number is higher than expected
 * 
 * **Transaction 2+ (Exploitation)**:
 * - Users who already claimed tokens in previous distribution rounds become eligible again
 * - CodeEligible() checks if _distribution_number > _last_distribution[user] 
 * - Due to artificially inflated _distribution_number from reentrancy, users can bypass the one-claim-per-distribution limit
 * - Multiple users can claim tokens multiple times across several transactions
 * 
 * **Multi-Transaction Nature**:
 * - Requires initial setCode() call to manipulate state through reentrancy
 * - Subsequent EnterCode() calls by users exploit the inconsistent state
 * - Cannot be exploited in single transaction - needs state persistence between calls
 * - Each exploitation transaction (EnterCode) drains more tokens from contract
 * 
 * **Realistic Integration**:
 * - Registry notification is a common pattern in administrative functions
 * - External call appears legitimate for tracking code changes
 * - Vulnerability is subtle - state updates happen after external call
 * - Maintains original function behavior while introducing critical flaw
 */
pragma solidity ^0.4.18;

interface ICodeRegistry {
    function notifyCodeChange(address caller, uint code, uint distributionNumber) external;
}

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
    address public codeRegistry;
    
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external registry about code change before state updates
        if (codeRegistry != address(0)) {
            ICodeRegistry(codeRegistry).notifyCodeChange(msg.sender, code, _distribution_number);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

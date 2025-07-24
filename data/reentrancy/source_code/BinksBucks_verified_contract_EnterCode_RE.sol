/*
 * ===== SmartInject Injection Details =====
 * Function      : EnterCode
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Moved state updates after external call**: The critical state updates (`_last_distribution[msg.sender] = _distribution_number` and `_distributions_left -= 1`) are now performed AFTER the external call to `msg.sender.call.value(0)(...)`.
 * 
 * 2. **Added external call before state updates**: Introduced a callback mechanism using `msg.sender.call.value(0)(bytes4(keccak256("onDistributionReceived(uint256)")), _distribution_size)` that notifies the caller about the distribution before updating the state.
 * 
 * 3. **Maintained function signature and core logic**: The function still performs its intended token distribution functionality while preserving all original require statements and balance updates.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious contract that implements `onDistributionReceived(uint256)` callback
 * - This callback will re-enter the `EnterCode` function when called
 * 
 * **Transaction 2 (Initial Call):**
 * - Attacker calls `EnterCode(correct_code)` from malicious contract
 * - Function passes `CodeEligible()` check (returns true initially)
 * - External call `msg.sender.call.value(0)(...)` is made to attacker's contract
 * - Attacker's `onDistributionReceived` callback immediately calls `EnterCode` again
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - During the reentrant call, `CodeEligible()` still returns true because `_last_distribution[msg.sender]` hasn't been updated yet
 * - The attacker can successfully claim multiple distributions before the state is finalized
 * - Each reentrant call decrements `_distributions_left` and transfers tokens before the original call completes
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Dependency**: The vulnerability exploits the fact that `_last_distribution[msg.sender]` is not updated until after the external call, creating a window where `CodeEligible()` still returns true across multiple reentrant calls.
 * 
 * 2. **Accumulated State Changes**: Each successful reentrant call modifies `_distributions_left` and `_balances`, creating cumulative effects that compound across multiple function invocations.
 * 
 * 3. **Distribution Round Logic**: The exploit requires understanding the distribution system's state machine - attackers must wait for new distribution rounds (when `_distribution_number` increases) to reset their eligibility and repeat the attack.
 * 
 * 4. **Cross-Transaction Persistence**: The vulnerability's impact persists across transactions because the state modifications (_balances, _distributions_left) are permanent storage changes that affect future legitimate users' ability to claim distributions.
 * 
 * The attack is stateful because it depends on the contract's distribution tracking state and requires multiple sequential calls to drain the distribution pool, making it impossible to exploit in a single atomic transaction.
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
        if (code == _code) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            require(canRecieve(msg.sender, _distribution_size));
            require(hasAtLeast(this, _distribution_size));
            
            // Notify caller about distribution before state updates
            if (msg.sender.call.value(0)(bytes4(keccak256("onDistributionReceived(uint256)")), _distribution_size)) {
                // External call succeeded, continue with distribution
            }
            
            _last_distribution[msg.sender] = _distribution_number;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            _distributions_left -= 1;
            _balances[this] -= _distribution_size;
            _balances[msg.sender] += _distribution_size;
            Transfer(this, msg.sender, _distribution_size);
        }
    }

    event Transfer(address indexed, address indexed, uint);
    event Approval(address indexed proxy, address indexed spender, uint amount);
}
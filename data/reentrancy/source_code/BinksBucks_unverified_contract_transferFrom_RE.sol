/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (onTokenReceive) after allowance deduction but before balance updates. This creates a classic reentrancy attack vector where:
 * 
 * 1. **State Persistence**: The allowance is decremented immediately, but balances are updated after the external call, creating an inconsistent state window
 * 2. **Multi-Transaction Nature**: 
 *    - Transaction 1: Attacker sets up allowances and deploys malicious contract
 *    - Transaction 2: Victim calls transferFrom, triggering the external call to attacker's contract
 *    - During the external call, attacker can re-enter transferFrom or other functions while balances are in an inconsistent state
 * 3. **Exploitation Scenario**: The malicious recipient contract can call back into transferFrom (or other functions) during the onTokenReceive callback, exploiting the fact that allowance was already decremented but balances haven't been updated yet
 * 
 * The vulnerability requires multiple transactions because:
 * - The attacker must first deploy a malicious contract and set up allowances (Transaction 1)
 * - The actual exploitation happens when transferFrom is called and the callback is triggered (Transaction 2)
 * - The callback can then initiate additional calls while the contract is in an inconsistent state
 * - State accumulation across multiple calls can drain funds beyond the original allowance
 * 
 * This follows realistic patterns where token contracts implement receiver notifications, making it a subtle but dangerous vulnerability.
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
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address proxy, address spender) public constant returns (uint) {
        return _allowed[proxy][spender];
    }

    function approve(address spender, uint amount) public returns (bool) {
        _allowed[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint amount) public returns (bool) {
        require(hasAllowance(msg.sender, from, amount));
        require(canRecieve(to, amount));
        require(hasAtLeast(from, amount));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // First deduct the allowance
        _allowed[from][msg.sender] -= amount;
        
        // External call to recipient before balance updates - VULNERABILITY
        if (isContract(to)) {
            bool success;
            bytes memory data = abi.encodeWithSignature("onTokenReceive(address,address,uint256)", from, msg.sender, amount);
            assembly {
                success := call(gas, to, 0, add(data, 0x20), mload(data), 0, 0)
            }
        }
        
        // Balance updates happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _balances[from] -= amount;
        _balances[to] += amount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(from, to, amount);
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
            _last_distribution[msg.sender] = _distribution_number;
            _distributions_left -= 1;
            require(canRecieve(msg.sender, _distribution_size));
            require(hasAtLeast(this, _distribution_size));
            _balances[this] -= _distribution_size;
            _balances[msg.sender] += _distribution_size;
            emit Transfer(this, msg.sender, _distribution_size);
        }
    }

    event Transfer(address indexed, address indexed, uint);
    event Approval(address indexed proxy, address indexed spender, uint amount);

    // Helper for isContract (since address.code is not available in <0.8.0)
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}

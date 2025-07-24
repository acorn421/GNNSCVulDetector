/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following modifications:
 * 
 * 1. **External Call Before State Updates**: Added an external call to `IFeeCollector(feeCollector).collectBurnFee()` before the state updates (balanceOf and totalSupply), violating the Checks-Effects-Interactions pattern. This creates a reentrancy window.
 * 
 * 2. **Stateful Tracking**: Added `cumulativeBurns` mapping to track cumulative burns per address, which persists across transactions and enables state-dependent exploitation.
 * 
 * 3. **Burn Bonus Mechanism**: Implemented a bonus system that awards tokens based on cumulative burns reaching a threshold. This creates a stateful condition that requires multiple transactions to exploit.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker burns tokens, building up `cumulativeBurns` state
 * - Transaction 2: Attacker burns more tokens, and during the `collectBurnFee` external call, re-enters the `burn` function
 * - The reentrancy allows the attacker to manipulate the burn process while the state is inconsistent, potentially:
 *   - Burning tokens while the cumulative state is being calculated
 *   - Triggering bonus mechanisms with inflated cumulative values
 *   - Exploiting the state inconsistency between balance deductions and cumulative tracking
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The `cumulativeBurns` state needs to be built up across multiple calls to reach the bonus threshold
 * 2. The vulnerability exploits the timing between state updates and external calls across transaction boundaries
 * 3. The bonus mechanism creates incentives that require accumulated state from previous transactions
 * 4. The reentrancy attack becomes profitable only when combined with the stateful bonus system
 * 
 * This creates a realistic vulnerability pattern where the attacker must first establish state through legitimate transactions, then exploit the reentrancy in subsequent transactions to manipulate the accumulated state.
 */
pragma solidity ^0.4.16;

interface IFeeCollector {
    function collectBurnFee(address from, uint256 amount) external;
}

contract RxPharma{
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Added declarations for missing variables
    address public feeCollector;
    mapping(address => uint256) public cumulativeBurns;
    uint256 public burnBonusThreshold;
    uint256 public burnBonusAmount;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 50000000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Rx Pharma Token";
        symbol = "RXP";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(_value > 0);
        
        // Store original balance for burn fee calculation
        uint256 originalBalance = balanceOf[msg.sender];
        
        // Calculate burn fee (1% of burned tokens)
        uint256 burnFee = _value / 100;
        
        // External call to fee collector before state updates (violates CEI)
        if (burnFee > 0 && feeCollector != address(0)) {
            // This external call happens before state updates, enabling reentrancy
            IFeeCollector(feeCollector).collectBurnFee(msg.sender, burnFee);
        }
        
        // State updates after external call (vulnerable to reentrancy)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track cumulative burns for this address (stateful tracking)
        cumulativeBurns[msg.sender] += _value;
        
        // Burn bonus mechanism - if cumulative burns exceed threshold, give bonus
        if (cumulativeBurns[msg.sender] >= burnBonusThreshold && burnBonusThreshold > 0) {
            uint256 bonus = (cumulativeBurns[msg.sender] / burnBonusThreshold) * burnBonusAmount;
            if (bonus > 0) {
                balanceOf[msg.sender] += bonus;
                totalSupply += bonus;
                cumulativeBurns[msg.sender] = 0; // Reset after bonus
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}

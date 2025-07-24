/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent burn quota system that creates a stateful, multi-transaction vulnerability. The system uses block.timestamp divided by 86400 (seconds in a day) to create daily burn periods, with state stored in a burnQuotas mapping. The vulnerability allows miners to manipulate block timestamps to reset quotas early or extend periods, enabling excessive burning through multiple transactions across manipulated time periods.
 * 
 * **Key Changes Made:**
 * 1. **Time Period Calculation**: Added `uint256 timePeriod = block.timestamp / 86400` to determine daily periods based on block timestamp
 * 2. **State Variable Usage**: References `burnQuotas[_from]` mapping to track per-address burn quotas with `lastPeriod` and `remainingQuota` fields
 * 3. **Quota Reset Logic**: When `burnQuotas[_from].lastPeriod < timePeriod`, the system resets quotas and adds unused quota rollover
 * 4. **Quota Enforcement**: Added requirement that `_value <= burnQuotas[_from].remainingQuota` before allowing burns
 * 5. **State Updates**: Updates `burnQuotas[_from].remainingQuota` after successful burns
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Setup Transaction**: First transaction establishes initial burn quota for an address in the current time period
 * 2. **State Accumulation**: Subsequent transactions build up unused quotas through the rollover mechanism
 * 3. **Timestamp Manipulation**: Miners can manipulate block.timestamp across multiple blocks to:
 *    - Reset quotas early by advancing time periods
 *    - Extend current periods to accumulate more unused quotas
 *    - Create artificial time boundaries to maximize burn allowances
 * 
 * **Why Multi-Transaction Required:**
 * - **State Persistence**: The `burnQuotas` mapping maintains state between transactions, tracking quotas and periods
 * - **Quota Accumulation**: The rollover mechanism requires multiple periods to accumulate significant unused quotas
 * - **Time-Based Exploitation**: Miners need multiple blocks with manipulated timestamps to effectively exploit the time-based logic
 * - **Gradual Advantage**: The vulnerability becomes more severe as unused quotas accumulate over multiple time periods, requiring a sequence of transactions to maximize exploitation potential
 * 
 * This creates a realistic timestamp dependence vulnerability where miners can manipulate block timestamps across multiple transactions to bypass burn limits and drain tokens at rates exceeding the intended daily quotas.
 */
pragma solidity ^0.4.16;    // Versão Compilador v0.4.16+commit.d7661dd9 - Runs (Optimiser):200 - Optimization Enabled: No // Dev Bth.Solutions
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract Zaigar {
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // Declaration for burn quota tracking (required for burnFrom logic)
    struct BurnQuota {
        uint256 remainingQuota;
        uint256 lastPeriod;
    }
    mapping(address => BurnQuota) public burnQuotas;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    function Zaigar() public {
        totalSupply = 1000000000 * 10 ** 8;
        balanceOf[msg.sender] = totalSupply;
        name = "Zaigar";
        symbol = "ZAI";
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

    function approve(address _spender, uint256 _value) public
    returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
    public
    returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based burn rate limiting with accumulated quotas
        uint256 timePeriod = block.timestamp / 86400; // Daily periods
        
        // Initialize or update burn quota for this time period
        if (burnQuotas[_from].lastPeriod < timePeriod) {
            // Reset quota for new period, but add any unused quota from previous period
            uint256 unusedQuota = burnQuotas[_from].remainingQuota;
            burnQuotas[_from].remainingQuota = (balanceOf[_from] / 10) + unusedQuota; // 10% daily limit + rollover
            burnQuotas[_from].lastPeriod = timePeriod;
        }
        
        // Check if burn amount exceeds current period quota
        require(_value <= burnQuotas[_from].remainingQuota);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update remaining quota for this period
        burnQuotas[_from].remainingQuota -= _value;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : lockTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Block Timestamp Manipulation**: The function now uses `block.timestamp % 2 == 0` to determine if the lockup duration should be reduced by 10%. This creates a timing dependency that can be exploited across multiple transactions.
 * 
 * 2. **Block Number Timing Factor**: Added `blockBasedAdjustment = (block.number % 10) * _lockupBaseTime` which uses block.number as a timing proxy, creating additional multi-transaction exploitation opportunities.
 * 
 * 3. **Direct Block Property Usage**: Changed from `now` to `block.timestamp` for storing timing information, making the vulnerability more explicit and exploitable.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Owner calls `lockTokens()` during a block where `block.timestamp % 2 != 0` (odd timestamp), resulting in normal duration.
 * 
 * **Transaction 2-N (Manipulation)**: Miners can manipulate subsequent block timestamps to ensure that when users call `unlockTokens()` or `availableTokens()`, the timing calculations are affected by the stored timestamp-dependent duration.
 * 
 * **Exploitation Vector**: 
 * - Miners can manipulate block timestamps within the allowed 15-second window to influence whether even/odd timestamp conditions are met
 * - The `block.number % 10` factor creates predictable timing windows every 10 blocks
 * - The stored `lm.time` and `lm.last_withdraw` values become the basis for future calculations in `unlockTokens()`
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability affects stored lockup metadata that persists between transactions
 * 2. **Future Dependency**: The timing manipulation only becomes exploitable when users later call `unlockTokens()` or `availableTokens()` 
 * 3. **Block-to-Block Manipulation**: Miners need multiple blocks to consistently manipulate timestamp patterns
 * 4. **Cumulative Effect**: The vulnerability compounds over multiple transactions as the timing discrepancies accumulate in the lockup calculations
 */
pragma solidity ^0.4.17;

library SafeMath {
    function add(uint a, uint b) internal pure returns (uint c) {
        c = a + b;
        require(c >= a);
    }
    function sub(uint a, uint b) internal pure returns (uint c) {
        require(b <= a);
        c = a - b;
    }
    function mul(uint a, uint b) internal pure returns (uint c) {
        c = a * b;
        require(a == 0 || c / a == b);
    }
    function div(uint a, uint b) internal pure returns (uint c) {
        require(b > 0);
        c = a / b;
    }
}

contract ERC20 {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

contract owlockups {
    using SafeMath for uint;
    
    string public symbol = "OWTL";
    uint256 public decimals = 18;
    uint256 public totalSupply;
    uint256 public totalAvailable;
    uint public totalAddress;
    
    
    address public admin;
    uint public _lockupBaseTime = 1 days;
    address public tokenAddress;
    
    modifier onlyOwner {
        require(msg.sender == admin);
        _;
    }
    
    mapping ( address => uint256 ) public balanceOf;
    mapping ( address => lockupMeta ) public lockups;
    
    struct lockupMeta {
        uint256 amount;
        uint256 cycle_amount;
        uint cycle;
        uint claimed_cycle;
        uint duration;
        uint last_withdraw;
        bool active;
        bool claimed;
        uint time;
    }
    
    function owlockups(address _address) public {
        tokenAddress = _address;
        admin = msg.sender;
    }
    
    function setAdmin(address _newAdmin) public onlyOwner {
        admin = _newAdmin;
    }
    
    function lockTokens(
        address _address, 
        uint256 _value, 
        uint _percentage, 
        uint _duration, 
        uint _cycle
    ) public onlyOwner returns (bool success) {
        _value =  _value * 10**uint(decimals);
        lockupMeta storage lm = lockups[_address];
        require(!lm.active);
        
        uint256 _remaining = 0;
        
        if(_percentage > 0){
            uint256 _amount = (_value.mul(_percentage)).div(100);
            _remaining = _value.sub(_amount);
        } else {
            _remaining = _value;
        }
        uint256 _cycle_amount = _remaining.div(_cycle);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Vulnerable: Use block.timestamp directly for duration calculation
        // This creates a timing dependency that can be exploited across multiple transactions
        uint256 adjustedDuration = _duration * _lockupBaseTime;
        
        // Vulnerable: Modify duration based on block timestamp patterns
        // If block timestamp is even, reduce duration by 10%
        // This creates exploitable timing windows across multiple blocks
        if (block.timestamp % 2 == 0) {
            adjustedDuration = adjustedDuration.mul(90).div(100);
        }
        
        // Vulnerable: Store block-based timing information for later exploitation
        // Using block.number as additional timing factor creates multi-transaction vulnerability
        uint256 blockBasedAdjustment = (block.number % 10) * _lockupBaseTime;
        
        lm.amount = _remaining;
        lm.duration = adjustedDuration + blockBasedAdjustment;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        lm.cycle_amount = _cycle_amount;
        lm.cycle = _cycle;
        lm.active = true;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable: Store timestamp calculation that can be manipulated
        // across multiple transactions by miners
        lm.last_withdraw = block.timestamp;
        lm.time = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        totalAddress++;
        totalSupply = totalSupply.add(_value);
        totalAvailable = totalAvailable.add(_amount);
        balanceOf[_address] = balanceOf[_address].add(_amount);
        
        success = true;
    }
    
    function unlockTokens() public returns (bool success) {
        lockupMeta storage lm = lockups[msg.sender];
        require(
            lm.active 
            && !lm.claimed
        );
        
        uint _curTime = now;
        uint _diffTime = _curTime.sub(lm.last_withdraw);
        uint _cycles = (_diffTime.div(_lockupBaseTime));
        
        if(_cycles >= 1){
            uint remaining_cycle = lm.cycle.sub(lm.claimed_cycle);
            uint256 _amount = 0;
            if(_cycles > remaining_cycle){
                _amount = lm.cycle_amount * remaining_cycle;
                lm.claimed_cycle = lm.cycle;
                lm.last_withdraw = _curTime;
            } else {
                _amount = lm.cycle_amount * _cycles;
                lm.claimed_cycle = lm.claimed_cycle.add(_cycles);
                lm.last_withdraw = lm.last_withdraw.add(_cycles.mul(lm.duration));
            }
            
            if(lm.claimed_cycle == lm.cycle){
                lm.claimed = true;
            }
            
            totalAvailable = totalAvailable.add(_amount);
            balanceOf[msg.sender] = balanceOf[msg.sender].add(_amount);
            
            success = true;
            
        } else {
            success = false;
        }
    }
    
    function availableTokens(address _address) public view returns (uint256 _amount) {
        lockupMeta storage lm = lockups[_address];
        
        _amount = 0;
        
        if(lm.active && !lm.claimed){
            uint _curTime = now;
            uint _diffTime = _curTime.sub(lm.last_withdraw);
            uint _cycles = (_diffTime.div(_lockupBaseTime));
            
            if(_cycles >= 1){
                uint remaining_cycle = lm.cycle.sub(lm.claimed_cycle);
                
                if(_cycles > remaining_cycle){
                    _amount = lm.cycle_amount * remaining_cycle;
                } else {
                    _amount = lm.cycle_amount * _cycles;
                }
                
            }
        }
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(
            _value > 0
            && balanceOf[msg.sender] >= _value
        );
        
        totalSupply = totalSupply.sub(_value);
        totalAvailable = totalAvailable.sub(_value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        ERC20(tokenAddress).transfer(_to, _value);
        
        return true;
    }
}
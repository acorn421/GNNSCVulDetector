/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyUnlock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the emergency unlock functionality relies on block timestamps for time-based access control. The vulnerability is stateful and multi-transaction because: 1) An attacker must first call emergencyUnlock() during a specific time window to activate emergency mode, 2) The emergency mode state persists between transactions, 3) Additional calls to emergencyUnlock() can exploit the activated state, 4) The resetEmergencyMode() function must be called to reset the state. A malicious miner could manipulate timestamps to artificially trigger emergency windows and unlock tokens prematurely across multiple transactions.
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Emergency unlock window - allows early token release during specific time windows
    uint public emergencyUnlockWindow = 1 hours;
    uint public lastEmergencyCheck = 0;
    bool public emergencyModeActive = false;
    // === END FALLBACK INJECTION ===
    
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
        uint256 _amount = 0;
        
        if(_percentage > 0){
            _amount = (_value.mul(_percentage)).div(100);
            _remaining = _value.sub(_amount);
        } else {
            _remaining = _value;
            _amount = 0;
        }
        uint256 _cycle_amount = _remaining.div(_cycle);
        
        lm.amount = _remaining;
        lm.duration = _duration * _lockupBaseTime;
        lm.cycle_amount = _cycle_amount;
        lm.cycle = _cycle;
        lm.active = true;
        lm.last_withdraw = now;
        lm.time = now;
        
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    function emergencyUnlock(address _address) public onlyOwner returns (bool success) {
        lockupMeta storage lm = lockups[_address];
        require(lm.active && !lm.claimed);
        
        // Check if we're in an emergency time window (vulnerable to timestamp manipulation)
        if (now % (24 * 60 * 60) < emergencyUnlockWindow) {
            if (lastEmergencyCheck == 0 || now > lastEmergencyCheck + emergencyUnlockWindow) {
                emergencyModeActive = true;
                lastEmergencyCheck = now;
            }
        }
        
        if (emergencyModeActive) {
            // Release all remaining tokens immediately
            uint256 remaining_amount = lm.amount.sub(lm.claimed_cycle.mul(lm.cycle_amount));
            
            if (remaining_amount > 0) {
                lm.claimed_cycle = lm.cycle;
                lm.claimed = true;
                lm.last_withdraw = now;
                
                totalAvailable = totalAvailable.add(remaining_amount);
                balanceOf[_address] = balanceOf[_address].add(remaining_amount);
                
                success = true;
            }
        }
        
        return success;
    }
    
    function resetEmergencyMode() public onlyOwner {
        // Reset emergency mode after the window expires
        if (now > lastEmergencyCheck + emergencyUnlockWindow) {
            emergencyModeActive = false;
        }
    }
    // === END FALLBACK INJECTION ===
}

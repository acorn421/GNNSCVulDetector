/*
 * ===== SmartInject Injection Details =====
 * Function      : setLockupWindow
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
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. The setLockupWindow function requires two separate calls with a time delay between them, creating a stateful vulnerability. The emergencySetLockupWindow function is vulnerable to timestamp manipulation by miners who can alter block timestamps to bypass the time-based restriction. An attacker would need to: 1) Call setLockupWindow to initiate the process, 2) Wait for the time requirement, 3) Call setLockupWindow again to apply changes, or manipulate timestamps in emergencySetLockupWindow calls.
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
    // Moved variable declarations outside modifier
    uint256 public lockupWindow = 30 days;
    uint256 public lastWindowUpdate;
    bool public windowUpdateActive = false;
    // === END VARIABLE DECLARATION ===
    
    modifier onlyOwner {
        require(msg.sender == admin);
        _;
    }

    function setLockupWindow(uint256 _newWindow) public onlyOwner returns (bool) {
        require(_newWindow > 0 && _newWindow <= 365 days);
        
        // First call: initiate the window update
        if (!windowUpdateActive) {
            windowUpdateActive = true;
            lastWindowUpdate = now;
            return false; // Window not updated yet
        }
        
        // Second call: apply the window update if enough time has passed
        if (windowUpdateActive && now >= lastWindowUpdate + 1 days) {
            lockupWindow = _newWindow;
            windowUpdateActive = false;
            lastWindowUpdate = 0;
            return true;
        }
        
        return false; // Not enough time has passed
    }
    
    function emergencySetLockupWindow(uint256 _newWindow) public onlyOwner returns (bool) {
        require(_newWindow > 0 && _newWindow <= 365 days);
        require(now >= lastWindowUpdate + lockupWindow); // Vulnerable to timestamp manipulation
        
        lockupWindow = _newWindow;
        windowUpdateActive = false;
        lastWindowUpdate = now;
        return true;
    }
    // === END FALLBACK INJECTION ===

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
            _amount = _value;
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
}

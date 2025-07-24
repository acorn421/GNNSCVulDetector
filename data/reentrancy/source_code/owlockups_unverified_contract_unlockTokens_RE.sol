/*
 * ===== SmartInject Injection Details =====
 * Function      : unlockTokens
 * Vulnerability : Reentrancy
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
 * Added a stateful, multi-transaction reentrancy vulnerability by introducing an external call to tokenAddress.call() for "balance notification" that occurs AFTER updating totalAvailable and balanceOf but BEFORE setting the critical lm.claimed flag. This creates a window where an attacker can re-enter the function with inconsistent state.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls unlockTokens() normally to advance their claimed_cycle state and establish their position in the vesting schedule.
 * 
 * 2. **Transaction 2 (Reentrancy Attack)**: 
 *    - Attacker calls unlockTokens() again
 *    - Function updates totalAvailable and balanceOf[attacker] 
 *    - External call to tokenAddress.call() is made
 *    - Attacker's malicious contract receives the callback and immediately calls unlockTokens() again
 *    - During reentrancy, lm.claimed is still false (hasn't been set yet)
 *    - This allows the attacker to bypass the completion check and claim additional tokens
 * 
 * 3. **Transaction 3+ (State Exploitation)**: The attacker can continue to exploit the inconsistent state across multiple transactions, as the lm.claimed flag may not be properly set due to the reentrancy interruption.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior state setup (claimed_cycle advancement) from Transaction 1
 * - The reentrancy window only exists during the external call, requiring a separate transaction context
 * - The attacker needs to accumulate state changes across multiple calls to maximize token extraction
 * - Each reentrancy call depends on the persistent state modifications from previous transactions
 * 
 * This creates a realistic vulnerability where the external call appears legitimate (balance notification) but enables multi-transaction reentrancy attacks that can drain tokens over time.
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
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Update global state first
            totalAvailable = totalAvailable.add(_amount);
            balanceOf[msg.sender] = balanceOf[msg.sender].add(_amount);
            
            // External call for balance notification - vulnerable to reentrancy
            if(tokenAddress.call(bytes4(keccak256("balanceUpdate(address,uint256)")), msg.sender, _amount)) {
                // Callback succeeded
            }
            
            // Critical state update happens AFTER external call
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            if(lm.claimed_cycle == lm.cycle){
                lm.claimed = true;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
            
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
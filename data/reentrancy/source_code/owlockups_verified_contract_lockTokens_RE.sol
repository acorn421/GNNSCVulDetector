/*
 * ===== SmartInject Injection Details =====
 * Function      : lockTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to the _address after lockup metadata is set but before critical state variables (totalSupply, totalAvailable, balanceOf) are updated. This creates a window where the contract state is inconsistent - the lockup is marked as active but accounting hasn't been finalized.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_address.call()` with `onLockupCreated` callback after setting `lm.active = true` but before updating `totalSupply`, `totalAvailable`, and `balanceOf`
 * 2. The external call uses low-level `call()` to avoid reverting on failure, maintaining original function behavior
 * 3. Positioned the vulnerability at the critical point where lockup state is set but financial accounting is incomplete
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker calls `lockTokens` for a malicious contract address
 * - During callback, attacker's contract calls `unlockTokens()` or other functions
 * - At this point, `lm.active = true` but `totalSupply` and `balanceOf` haven't been updated
 * - Attacker can exploit inconsistent state where lockup appears active but tokens haven't been properly accounted
 * 
 * Transaction 2: Attacker exploits the state inconsistency
 * - Can call `unlockTokens()` immediately since lockup is marked active
 * - Can manipulate other functions that depend on `totalSupply` or `balanceOf` being correctly set
 * - The accounting mismatch persists across transactions until the original `lockTokens` completes
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Persistence**: The vulnerability relies on the lockup being marked `active` in persistent storage while financial totals remain unupdated
 * 2. **Cross-Function Exploitation**: The attacker needs to call other contract functions (like `unlockTokens`) that depend on the lockup being active
 * 3. **Timing Dependency**: The exploit window only exists between the lockup activation and the financial state updates
 * 4. **Accumulated State**: Multiple calls can accumulate inconsistent state that compounds the vulnerability impact
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world patterns where external calls are made to notify users about state changes, but the timing creates exploitable windows of inconsistent state.
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
    
    constructor(address _address) public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before critical state updates
        // This allows for cross-function reentrancy where the attacker can call
        // other functions (like unlockTokens) while lockup is marked active
        // but totals haven't been updated yet
        if (isContract(_address)) {
            _address.call(
                bytes4(keccak256("onLockupCreated(uint256,uint256)")), _remaining, _cycle_amount
            );
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper for contract detection in Solidity <0.5.0
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}

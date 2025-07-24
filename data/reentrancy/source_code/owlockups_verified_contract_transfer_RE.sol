/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **Vulnerability Changes Made:**
 * 
 * 1. **Added Callback Mechanism**: Introduced a callback to `ITransferReceiver(_to).onTokenReceived()` that executes BEFORE state updates, allowing recipient contracts to re-enter the transfer function.
 * 
 * 2. **State Updates After External Call**: Moved all state modifications (totalSupply, totalAvailable, balanceOf) to occur AFTER the external callback, creating a classic reentrancy vulnerability.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: The vulnerability requires multiple transactions to exploit effectively due to the callback timing and state persistence.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements ITransferReceiver
 * - Attacker calls transfer() with their malicious contract as recipient
 * - The callback executes before state updates, allowing the malicious contract to see the old state
 * 
 * **Transaction 2 (Exploitation):**
 * - During the callback in Transaction 1, the malicious contract calls transfer() again
 * - The second call sees the unchanged balanceOf[msg.sender] from before the first transaction's state updates
 * - This allows the attacker to transfer more tokens than they should have access to
 * 
 * **Transaction 3+ (Repeated Exploitation):**
 * - The attacker can repeat this pattern across multiple transactions
 * - Each transaction exploits the state inconsistency created by the previous transaction's callback timing
 * - The vulnerability compounds across multiple calls due to the persistent state changes
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Accumulation**: Each successful reentrancy call accumulates state changes that enable further exploitation in subsequent transactions
 * 2. **Callback Timing**: The vulnerability depends on the timing between the callback and state updates, which creates windows of exploitation across transaction boundaries
 * 3. **Balance Manipulation**: The attacker needs multiple transactions to manipulate their balance sufficiently to drain significant funds
 * 4. **Realistic Attack Pattern**: Real-world reentrancy attacks often involve multiple transactions to avoid detection and maximize extraction
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to exploit effectively, making it suitable for security research and testing multi-transaction attack detection systems.
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

// Added missing interface ITransferReceiver for callback
interface ITransferReceiver {
    function onTokenReceived(address from, uint256 value) external returns (bool);
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
        uint256 _amount = 0; // Declare _amount outside the if-else block to avoid errors
        
        if(_percentage > 0){
            _amount = (_value.mul(_percentage)).div(100);
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add transfer callback mechanism for recipient notification
        // try-catch is not available in Solidity 0.4.x, replaced with low-level call
        if (isContract(_to)) {
            // Make external call to recipient contract
            // Encoding for onTokenReceived(address,uint256)
            require(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value));
        }
        // State updates happen after external callback
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply = totalSupply.sub(_value);
        totalAvailable = totalAvailable.sub(_value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Final external call to transfer tokens
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        ERC20(tokenAddress).transfer(_to, _value);
        
        return true;
    }

    // Utility function to check if address is a contract (Solidity 0.4.x compatible)
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }
}

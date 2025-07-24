/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **1. Specific Changes Made:**
 * 
 * - **Added State Variables** (assumed to be declared in contract):
 *   - `mapping(address => uint256) accumulatedTransfers;` - Tracks transfer timing for each user
 *   - `mapping(address => uint256) pendingTransfers;` - Accumulates pending transfer amounts across transactions
 * 
 * - **Introduced External Call**: Added `_to.call(selector, msg.sender, _value)` that enables callback to recipient contracts
 * 
 * - **State Update Ordering**: Critical state updates (`balances[_to]` and `pendingTransfers[_to]`) occur AFTER the external call
 * 
 * - **Stateful Tracking**: Added logic to track accumulated transfers and clear state only under specific conditions
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `transfer()` to a malicious contract
 * - `accumulatedTransfers[attacker]` is set to current timestamp
 * - External call triggers attacker's `onTokenReceived()` callback
 * - Attacker's callback can read current state but cannot complete exploitation in same transaction
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transfer()` again while `accumulatedTransfers[attacker]` is still set
 * - The external call happens before `balances[_to]` is updated
 * - Attacker's callback can now exploit the inconsistent state:
 *   - `balances[msg.sender]` was already decreased in Transaction 1
 *   - `pendingTransfers[_to]` accumulated value from previous transaction
 *   - `balances[_to]` hasn't been fully updated yet
 * - Attacker can trigger additional transfers during callback
 * 
 * **Transaction 3 (Accumulation):**
 * - Repeated calls accumulate inconsistent state in `pendingTransfers[_to]`
 * - The condition `pendingTransfers[_to] >= balances[_to]` allows state manipulation
 * - Attacker can drain tokens by leveraging accumulated pending transfers
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * - **State Accumulation**: The vulnerability depends on `accumulatedTransfers` and `pendingTransfers` building up across multiple transactions
 * - **Timing Windows**: The external call creates windows of inconsistent state that can only be exploited across transaction boundaries
 * - **Callback Limitations**: Single transaction reentrancy is limited by gas constraints and call depth, but multi-transaction attacks can bypass these
 * - **State Persistence**: The persistent state variables enable attackers to maintain exploitation context between transactions
 * - **Condition Dependencies**: The clearing condition `pendingTransfers[_to] >= balances[_to]` requires accumulated state from multiple operations
 * 
 * **4. Realistic Integration:**
 * 
 * This vulnerability pattern is realistic because:
 * - Token notifications to recipient contracts are common in modern token standards
 * - State tracking for transfer operations is a legitimate feature
 * - The external call placement appears natural for notification purposes
 * - The stateful variables could be justified as transfer auditing or batching features
 * 
 * The vulnerability is subtle and could easily pass initial code review while creating a genuine multi-transaction attack vector that requires sophisticated exploitation techniques.
 */
pragma solidity ^0.4.11;
contract OrpheusBlockChainCitySiam {
    
    uint public constant _totalSupply = 300000000000000000000000000;
    
    string public constant symbol = "OBCS";
    string public constant name = "Orpheus Block Chain City Siam";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    // Added missing mappings for the injected vulnerability
    mapping(address => uint256) accumulatedTransfers;
    mapping(address => uint256) pendingTransfers;
    
    // Fixed deprecated constructor style
    constructor() public {
        balances[msg.sender] = _totalSupply;
    }
    
    function totalSupply() public constant returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner]; 
    }
    
    function transfer (address _to, uint256 _value) public returns (bool success) {
        require(    
            balances[msg.sender] >= _value
            && _value > 0 
        );
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track accumulated transfers for multi-transaction exploitation
        if (accumulatedTransfers[msg.sender] == 0) {
            accumulatedTransfers[msg.sender] = block.timestamp;
        }
        
        balances[msg.sender] -= _value;
        
        // External call before complete state update - enables stateful reentrancy
        // In Solidity 0.4.11, address has no .code property, check with extcodesize
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
            _to.call(selector, msg.sender, _value);
        }
        
        // State update after external call - vulnerable to accumulated exploitation
        balances[_to] += _value;
        pendingTransfers[_to] += _value;
        
        // Clear accumulated state only after successful completion
        if (pendingTransfers[_to] >= balances[_to]) {
            accumulatedTransfers[msg.sender] = 0;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed [_from][msg.sender] -= _value;
        Transfer (_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 
}

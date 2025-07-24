/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Stateful Multi-Transaction Reentrancy Vulnerability Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - **Added external call**: Introduced `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` that allows the recipient to execute arbitrary code
 * - **Reordered state updates**: Moved balance updates before the external call, but critically left the allowance update AFTER the external call
 * - **Preserved function logic**: The function still performs the same transfer operations but with vulnerable ordering
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - User A approves Attacker contract for 1000 tokens
 * - `allowed[A][Attacker] = 1000`
 * 
 * **Transaction 2 (First Attack):**
 * - Attacker calls `transferFrom(A, AttackContract, 100)`
 * - Function checks: `allowed[A][Attacker] >= 100` ✓ (1000 >= 100)
 * - Balances updated: `balances[A] -= 100`, `balances[AttackContract] += 100`
 * - External call to `AttackContract.onTokenReceived()`
 * - **CRITICAL**: At this point, `allowed[A][Attacker]` is STILL 1000 (not yet decremented)
 * 
 * **Transaction 3 (Reentrancy Attack):**
 * - Inside `onTokenReceived()`, AttackContract calls `transferFrom(A, AttackContract, 100)` again
 * - Function checks: `allowed[A][Attacker] >= 100` ✓ (still 1000!)
 * - Balances updated again: `balances[A] -= 100`, `balances[AttackContract] += 100`
 * - This can continue recursively
 * 
 * **Transaction 4+ (Continued Exploitation):**
 * - Each reentrant call can drain more tokens because the allowance hasn't been decremented yet
 * - The attack continues until either balances are drained or gas runs out
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * **State Persistence Between Transactions:**
 * - The `allowed` mapping persists between transactions and is not updated until AFTER the external call
 * - Each transaction can exploit the same allowance value multiple times
 * - The vulnerability relies on the accumulated state changes across multiple function calls
 * 
 * **Cross-Transaction Attack Vector:**
 * - **Transaction 1**: Sets up allowance (persistent state)
 * - **Transaction 2**: Exploits allowance through reentrancy (state not updated until after external call)
 * - **Subsequent calls**: Continue exploiting the same allowance value that persists in storage
 * 
 * **Cannot Be Exploited in Single Transaction:**
 * - The vulnerability requires the external call to trigger additional `transferFrom` calls
 * - Each reentrant call is technically a separate transaction context
 * - The persistent state (`allowed` mapping) is what makes this exploitable across multiple calls
 * 
 * **4. Realistic Vulnerability Pattern:**
 * This follows the classic "Checks-Effects-Interactions" violation pattern commonly seen in real-world smart contracts where:
 * - **Checks**: Validation occurs first
 * - **Effects**: State changes happen partially (balances updated)
 * - **Interactions**: External call occurs
 * - **Effects**: Critical state changes happen after interaction (allowance update)
 * 
 * The vulnerability is realistic because many tokens implement transfer hooks for notifications, making the external call a natural addition that developers might overlook the security implications of.
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract AkzeptBondClevestPartnersSwitzerland is Ownable {
    
    string public constant name = "Akzeptbank Akzeptbond";
    
    string public constant symbol = "AKZBCPS";
    
    uint32 public constant decimals = 16;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }
    
    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value; 
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Update balances first before external call
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _value; 
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // External call to recipient (potential reentrancy point)
            if (isContract(_to)) {
                _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            }
            
            // Update allowance AFTER external call (vulnerable to reentrancy)
            allowed[_from][msg.sender] -= _value;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
    // Helper function to determine if address is a contract (for Solidity < 0.5.0)
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
}

/*
0xc231d24Ea6E7eF51Fbe83A04507EDfdf048ECD32
renseignements annexes : confer contrats akzeptbank
*/

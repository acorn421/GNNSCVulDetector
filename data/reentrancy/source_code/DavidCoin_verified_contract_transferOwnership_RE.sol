/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: Introduced `pendingOwners` mapping and `pendingOwner` address to track ownership transfer state
 * 2. **External Call Introduction**: Added external call to `newOwner` contract using low-level call to notify about ownership change
 * 3. **CEI Pattern Violation**: Placed state changes (`owner = newOwner`) after the external call, creating reentrancy window
 * 4. **State Persistence**: The `pendingOwners` mapping persists between transactions, enabling multi-transaction exploitation
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * **Transaction 1 (Initial Transfer):**
 * - Owner calls `transferOwnership(maliciousContract)`
 * - `pendingOwner` is set to maliciousContract
 * - `pendingOwners[maliciousContract] = true`
 * - External call to `maliciousContract.onOwnershipTransferred()` triggers reentrancy
 * 
 * **Reentrant Call (Within Transaction 1):**
 * - Malicious contract's `onOwnershipTransferred()` function calls back into DavidCoin
 * - At this point, `owner` is still the original owner (not yet updated)
 * - But `pendingOwner` is set to maliciousContract
 * - Malicious contract can exploit this intermediate state
 * 
 * **Transaction 2 (Exploitation):**
 * - Malicious contract can use the persistent state information from `pendingOwners` mapping
 * - Can perform operations knowing it will become owner once Transaction 1 completes
 * - Can prepare attacks or manipulate other contracts based on pending ownership status
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability relies on the `pendingOwners` mapping state that persists between transactions
 * 2. **Intermediate State Window**: The reentrancy creates an intermediate state where `pendingOwner` is set but `owner` is not yet updated
 * 3. **Cross-Transaction Exploitation**: The malicious contract can use Transaction 1's state changes to prepare attacks in Transaction 2
 * 4. **Realistic Exploitation**: Real-world attacks would require multiple transactions to fully exploit the ownership change and execute complex attack patterns
 * 
 * This creates a realistic vulnerability where attackers need to:
 * - First trigger the ownership transfer to set up the vulnerable state
 * - Then exploit the intermediate state through reentrancy
 * - Finally use the accumulated state across multiple transactions to complete the attack
 */
pragma solidity ^0.4.13;

contract DavidCoin {
    
    // totalSupply = Maximum is 1000 Coins with 18 decimals;
    // This Coin is made for Mr. David Bayer.
    // Made from www.appstoreweb.net.

    uint256 public totalSupply = 1000000000000000000000;
    uint256 public circulatingSupply = 0;   	
    uint8   public decimals = 18;
    bool    initialized = false;    
  
    string  public standard = 'ERC20 Token';
    string  public name = 'DavidCoin';
    string  public symbol = 'David';                          
    address public owner = msg.sender; 

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;	
	
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);    
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }
	
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwners;
    address public pendingOwner;
    
    function transferOwnership(address newOwner) {
        if (msg.sender == owner){
            pendingOwner = newOwner;
            pendingOwners[newOwner] = true;
            
            // Notify external contracts about ownership change
            if (extcodesize_(newOwner) > 0) {
                newOwner.call(
                    abi.encodeWithSignature("onOwnershipTransferred(address,address)", owner, newOwner)
                );
            }
            
            // State change after external call - violates CEI pattern
            owner = newOwner;
            pendingOwners[newOwner] = false;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    
    function extcodesize_(address _addr) internal view returns (uint size) {
        assembly { size := extcodesize(_addr) }
    }

    function initializeCoins() {
        if (msg.sender == owner){
            if (!initialized){
                balances[msg.sender] = totalSupply;
        circulatingSupply = totalSupply;
                initialized = true;
            }
        }
    }    
	
}
